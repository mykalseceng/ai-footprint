"""T3 Code: install, permission modes, paired clients, background work and account notes."""

import json
from pathlib import Path

from ai_footprint import checks
from ai_footprint.checks import local_code, steering, stolen_token
from ai_footprint.harnesses import registry
from ai_footprint.harnesses.common import Context
from ai_footprint.harnesses.t3code import collector as t3
from ai_footprint.model import (
    OTHER_TOOL_LOGIN,
    USAGE,
    AccountNote,
    HostReport,
    StoreKind,
    ToolReport,
)
from tests.conftest import FakeSystem, build_t3code_home

T3 = registry()["t3code"]


def context(home: Path, env: dict[str, str] | None = None) -> Context:
    system = FakeSystem()
    system.env.update(env or {})
    return Context(home=home, system=system, now=1_790_000_000, scan=False)


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


def test_the_app_bundle_is_the_binary_and_markers_are_read_from_its_archive(tmp_path: Path):
    asar = build_t3code_home(tmp_path)
    found = T3.detect(context(tmp_path))
    assert found.installed
    [binary] = found.binaries
    assert binary.version == "0.1.5"
    assert binary.resolved == str(asar)


def test_the_data_folder_alone_marks_it_installed(tmp_path: Path):
    (tmp_path / ".t3").mkdir()
    assert T3.detect(context(tmp_path)).installed
    assert not T3.detect(context(tmp_path / "empty")).installed


def test_t3codehome_moves_the_data_folder(tmp_path: Path):
    build_t3code_home(tmp_path)
    moved = tmp_path / "elsewhere"
    (tmp_path / ".t3").rename(moved)
    report = T3.collect(context(tmp_path, {"T3CODE_HOME": str(moved)}))
    assert any(a.path.startswith(str(moved)) for a in report.artifacts)


def test_full_access_threads_are_an_approval_exposure_with_the_t3_fix(tmp_path: Path):
    build_t3code_home(tmp_path)
    report = T3.collect(context(tmp_path))
    assert settings(report)[t3.THREADS_FULL_ACCESS] == "2 of 3 threads"
    [exposure] = steering.rule_no_approval(report, rule_ctx(tmp_path))
    assert exposure.fix is not None
    assert "Supervised" in exposure.fix.commands[0].text


def test_supervised_threads_raise_nothing(tmp_path: Path):
    build_t3code_home(tmp_path, threads=("approval-required",))
    report = T3.collect(context(tmp_path))
    assert not steering.rule_no_approval(report, rule_ctx(tmp_path))


def test_a_paired_phone_is_a_signal_but_the_desktop_app_is_not(tmp_path: Path):
    build_t3code_home(tmp_path)
    report = T3.collect(context(tmp_path))
    assert not stolen_token.rule_remote_control(report, rule_ctx(tmp_path))

    phone = tmp_path / "phone"
    scopes = '["terminal:operate", "filesystem:write", "relay:read"]'
    build_t3code_home(phone, sessions=(("desktop", "[]"), ("mobile", scopes)))
    report = T3.collect(context(phone))
    [signal] = stolen_token.rule_remote_control(report, rule_ctx(phone))
    assert "Paired mobile client" in signal.statement
    assert "terminal:operate and filesystem:write" in signal.statement


def test_the_account_token_is_plaintext_and_server_keys_are_one_credential(tmp_path: Path):
    build_t3code_home(tmp_path)
    report = T3.collect(context(tmp_path))
    account, keys = report.credentials
    assert account.provider == "T3 account (Clerk)"
    assert [t.field for t in account.tokens] == ["__clerk_client_jwt"]
    assert keys.local_service and keys.location.endswith("secrets")
    assert "2 key files" in keys.protection


def test_the_background_service_and_enabled_tasks_run_unattended(tmp_path: Path):
    build_t3code_home(tmp_path)
    report = T3.collect(context(tmp_path))
    [service] = [x for x in report.extensions if x.kind == "service"]
    assert service.autostart
    assert service.detail.endswith("/.t3/bin/t3 serve")


def test_driven_harnesses_are_named_by_their_display_name(tmp_path: Path):
    build_t3code_home(tmp_path)
    report = T3.collect(context(tmp_path))
    assert settings(report)["agents driven"] == "Claude Code (3 threads)"


def other_tool_logins(home: Path) -> None:
    """A Codex ChatGPT login and a signed-in Claude Code config, as T3 Code finds them."""
    (home / ".codex").mkdir()
    tokens = {"account_id": "workspace-1", "id_token": "header.payload.signature"}
    (home / ".codex" / "auth.json").write_text(json.dumps({"tokens": tokens}))
    claude = {"userID": "install-1", "oauthAccount": {"accountUuid": "account-1"}}
    (home / ".claude.json").write_text(json.dumps(claude))


def usage(report: ToolReport) -> list[AccountNote]:
    return [n for n in report.account if n.topic == USAGE]


def test_usage_events_and_relay_traces_are_on_and_carry_other_tools_account_ids(tmp_path: Path):
    build_t3code_home(tmp_path)
    other_tool_logins(tmp_path)
    report = T3.collect(context(tmp_path))
    [events, codex, claude, traces] = usage(report)
    assert events.text.startswith("Usage events to ingest.t3.codes: on by default.")
    assert "unsalted SHA-256" in events.text
    assert codex.signal == claude.signal == OTHER_TOOL_LOGIN
    assert "Codex CLI's login file ~/.codex/auth.json" in codex.text
    assert "Claude Code's login file ~/.claude.json" in claude.text
    assert "workspace-1" not in codex.text and "account-1" not in claude.text
    assert traces.text.startswith("Relay connection traces to us-east-1.aws.edge.axiom.co: on")
    ctx = rule_ctx(tmp_path)
    found = {e.id: e for rule in checks.TOOL_RULES for e in rule.fn(report, ctx)}
    assert {"t3code:usage-data", "t3code:other-logins"} <= set(found)
    fix = found["t3code:other-logins"].fix
    assert fix is not None and "T3CODE_TELEMETRY_ENABLED=false" in fix.commands[0].text


def test_the_service_env_turns_both_streams_off_and_the_shell_overrides_it(tmp_path: Path):
    build_t3code_home(tmp_path)
    other_tool_logins(tmp_path)
    (tmp_path / ".t3" / "service.env").write_text("T3CODE_TELEMETRY_ENABLED=false\n")
    off = usage(T3.collect(context(tmp_path)))
    assert [n.concern for n in off] == [False, False]
    assert "off (T3CODE_TELEMETRY_ENABLED=false in ~/.t3/service.env)" in off[0].text
    shell = usage(T3.collect(context(tmp_path, {"T3CODE_TELEMETRY_ENABLED": "1"})))
    assert shell[0].concern
    assert "on (T3CODE_TELEMETRY_ENABLED=1 in the environment)" in shell[0].text


def test_relay_traces_follow_the_otel_switch_before_the_generic_one(tmp_path: Path):
    build_t3code_home(tmp_path)
    env = {"T3CODE_OTEL_SDK_DISABLED": "false", "OTEL_SDK_DISABLED": "true"}
    traces = usage(T3.collect(context(tmp_path, env)))[-1]
    assert traces.concern
    env = {"OTEL_SDK_DISABLED": "true"}
    traces = usage(T3.collect(context(tmp_path, env)))[-1]
    assert not traces.concern


def test_an_unreadable_state_db_yields_no_settings_rows(tmp_path: Path):
    (tmp_path / ".t3" / "userdata").mkdir(parents=True)
    (tmp_path / ".t3" / "userdata" / "statev2.sqlite").write_text("not a database")
    report = T3.collect(context(tmp_path))
    assert t3.THREADS_FULL_ACCESS not in settings(report)
    assert report.installed


def test_a_safestorage_token_is_encrypted_not_plaintext(tmp_path: Path):
    build_t3code_home(tmp_path)
    token_file = tmp_path / ".t3" / "userdata" / "clerk-tokens.json"
    token_file.write_text('{"__clerk_client_jwt": "enc:djEwAAAAciphertext"}')
    report = T3.collect(context(tmp_path))
    account = next(c for c in report.credentials if c.provider == "T3 account (Clerk)")
    assert account.store is StoreKind.ENCRYPTED_FILE
    assert account.tokens == []
    assert "safeStorage" in account.protection
    [plain] = local_code.rule_plaintext_credentials(report, rule_ctx(tmp_path))
    assert "T3 account" not in plain.statement


def test_a_raw_token_is_plaintext_and_inspected(tmp_path: Path):
    build_t3code_home(tmp_path)
    token_file = tmp_path / ".t3" / "userdata" / "clerk-tokens.json"
    token_file.write_text('{"__clerk_client_jwt": "raw:opaque-value-123"}')
    account = next(
        c for c in T3.collect(context(tmp_path)).credentials if c.provider == "T3 account (Clerk)"
    )
    assert account.store is StoreKind.FILE
    [token] = account.tokens
    assert token.length == len("opaque-value-123")
