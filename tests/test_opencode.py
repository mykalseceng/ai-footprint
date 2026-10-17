"""OpenCode collector: server password evidence, 2.x tables, presence and process matching."""

import json
import sqlite3
import time
from pathlib import Path

import pytest

from ai_footprint import rules
from ai_footprint.collectors import opencode
from ai_footprint.collectors.common import Context
from ai_footprint.model import Category, HostReport
from ai_footprint.system import ProbeResult
from tests.conftest import FakeSystem, build_opencode_home

PS = (
    "  50614 50222 Fri Oct 16 14:37:00 2026 opencode2\n"
    "  50615 50614 Fri Oct 16 14:37:01 2026 /x/opencode.exe serve --service\n"
)
LSOF = (
    "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
    "opencode 50615 me 7u IPv4 0x1 0t0 TCP 127.0.0.1:49374 (LISTEN)\n"
    "opencode 50615 me 9u IPv4 0x2 0t0 TCP 127.0.0.1:49374->127.0.0.1:60006 (ESTABLISHED)\n"
    "opencode 50614 me 8u IPv4 0x3 0t0 TCP 127.0.0.1:60006->127.0.0.1:49374 (ESTABLISHED)\n"
    "opencode 50614 me 9u IPv4 0x4 0t0 TCP 10.0.0.2:51000->104.18.0.1:443 (ESTABLISHED)\n"
)
PASSWORD = "p" * 43


def context(home: Path) -> Context:
    system = FakeSystem()

    def respond(argv: list[str]) -> ProbeResult | None:
        name = Path(argv[0]).name
        if name == "ps":
            return ProbeResult(0, PS, "")
        if name == "lsof":
            return ProbeResult(0, LSOF if "-iTCP" in argv else "", "")
        return None

    system.responders.append(respond)
    return Context(home=home, system=system, now=time.time(), scan=False)


def register(home: Path, record: dict) -> Path:
    state = home / ".local" / "state" / "opencode"
    state.mkdir(parents=True, exist_ok=True)
    path = state / "service.json"
    path.write_text(json.dumps(record))
    path.chmod(0o600)
    return path


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


def server_setting(home: Path):
    report, _facts = opencode.collect(context(home))
    return [s for s in report.settings if "server" in s.key], report


def test_a_registration_with_a_password_clears_the_server_check(tmp_path: Path):
    build_opencode_home(tmp_path)
    register(tmp_path, {"url": "http://127.0.0.1:49374", "pid": 50615, "password": PASSWORD})
    [setting], report = server_setting(tmp_path)
    assert setting.key == "local server 127.0.0.1:49374"
    assert setting.value == "password set (~/.local/state/opencode/service.json)"
    assert not setting.concern
    assert rules.rule_open_server(report, rule_ctx(tmp_path)) == []
    assert rules._needs_local_server(report, rule_ctx(tmp_path)) == ""


def test_a_registration_without_a_password_is_an_open_server(tmp_path: Path):
    build_opencode_home(tmp_path)
    register(tmp_path, {"url": "http://127.0.0.1:49374", "pid": 50615})
    [setting], report = server_setting(tmp_path)
    assert setting.concern
    [found] = rules.rule_open_server(report, rule_ctx(tmp_path))
    assert "registration records no password" in found.statement


@pytest.mark.parametrize("record", [None, {"url": "http://127.0.0.1:1111", "password": PASSWORD}])
def test_without_a_registration_for_the_port_the_password_is_not_checked(
    tmp_path: Path, record: dict | None
):
    build_opencode_home(tmp_path)
    if record:
        register(tmp_path, record)
    [setting], report = server_setting(tmp_path)
    assert setting.key == "listening server 127.0.0.1:49374"
    assert not setting.concern
    reason = rules._needs_local_server(report, rule_ctx(tmp_path))
    assert reason == "no registration on disk records the listening server's password"


def test_both_service_files_are_credential_locations(tmp_path: Path):
    build_opencode_home(tmp_path)
    state = register(tmp_path, {"url": "http://127.0.0.1:49374", "password": PASSWORD})
    config = tmp_path / ".config" / "opencode"
    config.mkdir(parents=True)
    (config / "service.json").write_text(json.dumps({"password": PASSWORD}))
    report, _facts = opencode.collect(context(tmp_path))
    servers = [c for c in report.credentials if c.provider == "OpenCode local server"]
    assert {c.location for c in servers} == {str(state), str(config / "service.json")}
    assert len({c.tokens[0].fingerprint for c in servers}) == 1


def test_the_2x_session_process_is_matched_and_incoming_sockets_are_not_destinations(
    tmp_path: Path,
):
    build_opencode_home(tmp_path)
    report, _facts = opencode.collect(context(tmp_path))
    assert [p.pid for p in report.processes] == [50614, 50615]
    live = [e.host for e in report.endpoints if e.source == "live-socket"]
    assert "127.0.0.1:60006" not in live
    assert "104.18.0.1:443" in live and "127.0.0.1:49374 (listening)" in live


def test_v2_tables_are_counted_once_with_legacy_rows(tmp_path: Path):
    db = build_opencode_home(tmp_path)
    with sqlite3.connect(db) as conn:
        conn.execute("INSERT INTO session VALUES ('a', NULL, 1775524598683)")
        conn.execute("CREATE TABLE session_v2 (id text, share_url text, time_created integer)")
        conn.executemany(
            "INSERT INTO session_v2 VALUES (?, ?, ?)",
            [("a", None, 1775524598683), ("b", "https://x", 1792186633430)],
        )
        conn.execute("CREATE TABLE message (id text)")
        conn.execute("CREATE TABLE session_message (id text)")
        conn.executemany("INSERT INTO message VALUES (?)", [("m1",)])
        conn.executemany("INSERT INTO session_message VALUES (?)", [("m1",), ("m2",)])
    report, _facts = opencode.collect(context(tmp_path))
    assert report.stats["sessions"] == "2"
    assert report.stats["messages"] == "2"
    assert report.stats["first session"] == "2026-04-07"
    assert report.stats["last session"] == "2026-10-16"
    shared = {s.key: s.value for s in report.settings}.get("shared sessions")
    assert shared == "1"


def test_legacy_only_databases_still_report_their_counts(tmp_path: Path):
    build_opencode_home(tmp_path)
    report, _facts = opencode.collect(context(tmp_path))
    assert report.stats["sessions"] == "0"
    assert "messages" not in report.stats


def test_a_config_folder_alone_is_installed_for_both_detect_and_collect(tmp_path: Path):
    (tmp_path / ".config" / "opencode").mkdir(parents=True)
    ctx = context(tmp_path)
    assert opencode.detect(ctx).installed
    report, _facts = opencode.collect(ctx)
    assert report.installed


def test_nothing_on_disk_is_not_installed(tmp_path: Path):
    ctx = context(tmp_path)
    assert not opencode.detect(ctx).installed
    assert not opencode.collect(ctx)[0].installed


def test_snapshots_are_not_conversations_but_prompt_history_is(tmp_path: Path):
    roots = opencode._roots(context(tmp_path))
    by_label = {s.label: s.category for s in opencode._artifact_specs(roots)}
    assert by_label["Snapshots"] is Category.CACHE
    assert by_label["Prompt history"] is Category.SESSION
    assert by_label["Server registration"] is Category.CREDENTIAL
