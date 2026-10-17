"""Codex CLI facts are stated as recorded: thread modes, remote control, sockets, plugins."""

import json
import sqlite3
import time
from pathlib import Path

from ai_footprint import accounts, extensions, figures, rules
from ai_footprint.collectors import codex
from ai_footprint.collectors.common import Context, shell_shortcuts
from ai_footprint.model import HostReport, ProcessInfo, ToolReport
from ai_footprint.system import ProbeResult
from tests.conftest import FakeSystem

UPDATED = 1792199218
"""2026-10-17 01:06:58 UTC."""


def state_db(root: Path, sql: str, rows: list[tuple] | None = None) -> None:
    root.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(root / "state_5.sqlite") as conn:
        conn.execute(sql)
        if rows:
            marks = ",".join("?" * len(rows[0]))
            table = sql.split()[2]
            conn.executemany(f"INSERT INTO {table} VALUES ({marks})", rows)  # noqa: S608


THREADS = "CREATE TABLE threads (approval_mode TEXT, sandbox_policy TEXT, updated_at INTEGER)"
ENROLLMENTS = (
    "CREATE TABLE remote_control_enrollments (app_server_client_name TEXT, server_name TEXT, "
    "remote_control_enabled INTEGER, updated_at INTEGER)"
)


def codex_report(**fields) -> ToolReport:
    return ToolReport(name="codex", display_name="Codex CLI", installed=True, **fields)


def rule_context(home: Path) -> rules.RuleContext:
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


def test_thread_approval_is_absent_without_a_state_db_or_threads_table(tmp_path: Path):
    assert codex.thread_approval(tmp_path) is None
    state_db(tmp_path, "CREATE TABLE other (x TEXT)")
    assert codex.thread_approval(tmp_path) is None


def test_empty_threads_table_is_read_and_not_a_concern(tmp_path: Path):
    state_db(tmp_path, THREADS)
    setting = codex.thread_approval(tmp_path)
    assert setting is not None
    assert setting.value == "0 of 0 recorded CLI threads"
    assert not setting.concern


def test_threads_that_ran_with_approval_off_are_counted_by_sandbox(tmp_path: Path):
    state_db(
        tmp_path,
        THREADS,
        [
            ("never", json.dumps({"type": "danger-full-access"}), UPDATED - 86400),
            ("never", json.dumps({"type": "danger-full-access"}), UPDATED),
            ("never", "disabled", UPDATED - 10),
            ("on-request", json.dumps({"type": "read-only"}), UPDATED + 999999),
        ],
    )
    setting = codex.thread_approval(tmp_path)
    assert setting is not None
    assert setting.key == rules.THREADS_WITHOUT_APPROVAL
    assert setting.value == (
        "3 of 4 recorded CLI threads (2 sandbox danger-full-access, 1 sandbox disabled; "
        "latest updated 2026-10-17)"
    )
    assert setting.concern


def test_desktop_and_guardian_threads_are_named_but_not_counted_as_cli(tmp_path: Path):
    state_db(
        tmp_path,
        "CREATE TABLE threads (approval_mode TEXT, sandbox_policy TEXT, originator TEXT, "
        "source TEXT, updated_at INTEGER)",
        [
            ("never", "danger-full-access", "codex-tui", "cli", UPDATED - 50),
            ("on-request", "read-only", "codex-tui", "cli", UPDATED),
            ("never", "managed", "Codex Desktop", "vscode", UPDATED + 99),
            ("never", "managed", "codex-tui", '{"subagent":{"other":"guardian"}}', UPDATED + 99),
            ("on-request", "managed", "Codex Desktop", "vscode", UPDATED),
        ],
    )
    setting = codex.thread_approval(tmp_path)
    assert setting is not None
    assert setting.value == (
        "1 of 2 recorded CLI threads (1 sandbox danger-full-access; latest updated 2026-10-17); "
        "also with approval_mode=never, not counted: 1 desktop-app thread, 1 guardian review"
    )


def test_recorded_threads_drive_the_no_approval_signal_and_figure(tmp_path: Path):
    state_db(tmp_path, THREADS, [("never", "danger-full-access", UPDATED)])
    setting = codex.thread_approval(tmp_path)
    assert setting is not None
    report = codex_report(settings=[setting])
    [found] = rules.rule_no_approval(report, rule_context(tmp_path))
    assert "threads with approval_mode=never: 1 of 1 recorded CLI threads" in found.statement
    report.exposures = [found]
    figure = figures.approval(report)
    assert figure.value == "found"
    assert "threads with approval_mode=never = 1 of 1" in figure.detail


def test_threads_that_all_asked_are_read_as_not_found(tmp_path: Path):
    state_db(tmp_path, THREADS, [("on-request", "read-only", UPDATED)])
    setting = codex.thread_approval(tmp_path)
    assert setting is not None
    report = codex_report(settings=[setting])
    assert rules.rule_no_approval(report, rule_context(tmp_path)) == []
    assert figures.approval(report).value == "not found"
    assert rules._needs_approval_setting(report, rule_context(tmp_path)) == ""


def test_cloud_access_note_makes_no_claim_about_cloud_tasks(tmp_path: Path):
    (tmp_path / ".codex-global-state.json").write_text(
        json.dumps(
            {
                "electron-persisted-atom-state": {"codexCloudAccess": "enabled"},
                "electron-remote-hosted-pip-task-visibility-state": {"a": 1, "b": 2},
            }
        )
    )
    [note] = accounts._codex_data(codex_report(), tmp_path, {})
    assert note.text == "Codex cloud access: enabled; cloud-linked repos: none."
    assert not note.concern


def test_mobile_setup_flag_alone_is_stated_and_not_a_concern(tmp_path: Path):
    (tmp_path / ".codex-global-state.json").write_text(
        json.dumps({"codex-mobile-has-connected-device": True})
    )
    [note] = accounts._codex_remote({}, tmp_path)
    assert "codex-mobile-has-connected-device = true" in note.text
    assert "can drive" not in note.text
    assert not note.concern


def test_enabled_remote_control_enrollment_is_a_concern_with_its_record(tmp_path: Path):
    state_db(tmp_path, ENROLLMENTS, [("Codex Desktop", "Studio", 1, UPDATED)])
    config = {"desktop": {"keepRemoteControlAwakeWhilePluggedIn": True}}
    enrolled, awake = accounts._codex_remote(config, tmp_path)
    assert enrolled.text == (
        "Remote control is enabled for server Studio through client Codex Desktop "
        "(updated 2026-10-17). Which devices are paired now is not recorded locally."
    )
    assert enrolled.source == "~/.codex/state_5.sqlite remote_control_enrollments"
    assert enrolled.concern
    assert awake.text == "desktop.keepRemoteControlAwakeWhilePluggedIn = true."


def test_disabled_enrollment_and_missing_table_raise_no_concern(tmp_path: Path):
    assert accounts._codex_remote({}, tmp_path) == []
    state_db(tmp_path, ENROLLMENTS, [("Codex Desktop", "Studio", 0, UPDATED)])
    [note] = accounts._codex_remote({}, tmp_path)
    assert note.text.startswith("Remote control is not enabled")
    assert not note.concern


def test_codex_log_markers_need_the_codex_binary_to_know_them(tmp_path: Path):
    root = tmp_path / ".codex"
    (root / "log").mkdir(parents=True)
    (root / "log" / "codex-tui.log").write_text(
        "Your access token could not be refreshed. Please run /login\n"
    )
    ctx = Context(home=tmp_path, system=FakeSystem(), now=time.time())
    assert accounts._codex_detect(ctx, codex_report(), root, "") == []
    binary = tmp_path / "codex"
    binary.write_bytes(b"\0".join(m.encode() for m in codex.LOG_MARKERS))
    [note] = accounts._codex_detect(ctx, codex_report(), root, str(binary))
    assert note.text.startswith("Auth events in local logs: token refresh failed: 1 times")
    assert "asked to log in again" not in note.text


def test_rollouts_count_plain_and_compressed_files_in_both_session_folders(tmp_path: Path):
    for rel in (
        "sessions/2026/10/rollout-a.jsonl",
        "sessions/2026/10/rollout-b.jsonl.zst",
        "archived_sessions/rollout-c.jsonl",
        "archived_sessions/rollout-d.jsonl.zst",
        "sessions/2026/10/notes.txt",
    ):
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}")
    assert codex._stats(tmp_path)["session rollouts"] == "4"


def test_codex_inside_another_apps_bundle_is_not_codex_cli():
    found = [
        ProcessInfo(1, "", "/Users/me/.nvm/bin/codex resume"),
        ProcessInfo(2, "", "/Applications/ChatGPT.app/Contents/MacOS/codex app-server"),
    ]
    assert [p.pid for p in codex._cli_processes(found)] == [1]


def test_live_sockets_to_one_host_become_one_row_with_a_count(tmp_path: Path):
    lsof = (
        "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
        "codex 7 me 1u IPv4 0x1 0t0 TCP 10.0.0.2:5001->104.18.32.47:443 (ESTABLISHED)\n"
        "codex 7 me 2u IPv4 0x2 0t0 TCP 10.0.0.2:5002->104.18.32.47:443 (ESTABLISHED)\n"
        "codex 8 me 3u IPv4 0x3 0t0 TCP 10.0.0.2:5003->104.18.32.47:443 (ESTABLISHED)\n"
        "codex 8 me 4u IPv4 0x4 0t0 TCP 10.0.0.2:5004->160.79.104.10:443 (ESTABLISHED)\n"
    )
    system = FakeSystem()
    system.responders.append(
        lambda argv: ProbeResult(0, lsof, "") if Path(argv[0]).name == "lsof" else None
    )
    ctx = Context(home=tmp_path, system=system, now=time.time())
    report = codex_report(processes=[ProcessInfo(7, "", "codex"), ProcessInfo(8, "", "codex")])
    live = [e for e in codex._endpoints(ctx, tmp_path, report) if e.source == "live-socket"]
    assert [(e.host, e.count, e.purpose) for e in live] == [
        ("104.18.32.47:443", 3, "open sockets from pid 7, 8"),
        ("160.79.104.10:443", 1, "open sockets from pid 8"),
    ]


def test_plugin_mcp_servers_marked_disabled_do_not_start_automatically(tmp_path: Path):
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "off": {"command": "/bin/echo", "enabled": False},
                    "on": {"command": "/bin/echo"},
                }
            }
        )
    )
    rows = {r.name: r for r in extensions.plugin_mcp_rows(tmp_path, "codex", "p@m")}
    assert not rows["off"].autostart
    assert rows["off"].notes.startswith("disabled")
    assert rows["on"].autostart


def test_shell_shortcuts_with_the_bypass_flag_are_reported(tmp_path: Path):
    (tmp_path / ".zshrc").write_text(
        f"# alias old='codex {codex.BYPASS_FLAG}'\nalias codex-yolo=\"codex {codex.BYPASS_FLAG}\"\n"
    )
    ctx = Context(home=tmp_path, system=FakeSystem(), now=0.0)
    [found] = shell_shortcuts(ctx, codex.BYPASS_FLAG)
    assert found.key == "~/.zshrc:2"
    assert found.concern
