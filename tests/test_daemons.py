"""Daemons: tool processes launchd started or that listen, read from ps and lsof only."""

import time
from pathlib import Path

from ai_footprint import daemons, rules
from ai_footprint.collectors.common import Context
from ai_footprint.host import listeners, processes
from ai_footprint.model import BinaryInfo, Daemon, HostReport, Listener, ProcessInfo, ToolReport
from ai_footprint.system import ProbeResult
from tests.conftest import FakeSystem

PS = (
    "  47165     1 Fri Oct  9 10:25:32 2026 /Users/me/.codex/packages/app-server-daemon/releases/"
    "0.162.0-aarch64-apple-darwin/bin/codex app-server --listen unix:// --managed-daemon\n"
    "  49573     1 Tue Oct  6 09:33:36 2026 /Users/me/.codex/packages/app-server-daemon/releases/"
    "0.161.0-aarch64-apple-darwin/bin/codex app-server daemon pid-update-loop\n"
    "  68124 66577 Fri Oct  9 18:22:52 2026 /Applications/Codex.app/Contents/MacOS/codex "
    "app-server --listen stdio://\n"
)
LSOF_TCP = (
    "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
    "opencode 59569 me 7u IPv4 0x1 0t0 TCP 127.0.0.1:49374 (LISTEN)\n"
)


def lsof_unix(path: Path) -> str:
    return (
        "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
        "codex 47165 me 7u unix 0x1 0t0 ->0xe4eb\n"
        f"codex 47165 me 30u unix 0x3f 0t0 {path}\n"
    )


def system_with(ps: str, tcp: str, unix: str) -> FakeSystem:
    system = FakeSystem()

    def respond(argv: list[str]) -> ProbeResult | None:
        name = Path(argv[0]).name
        if name == "ps":
            return ProbeResult(0, ps, "")
        if name == "lsof":
            return ProbeResult(0, tcp if "-iTCP" in argv else unix, "")
        return None

    system.responders.append(respond)
    return system


def host(home: Path) -> HostReport:
    return HostReport(
        os="macOS",
        kernel="",
        arch="arm64",
        hostname="mac",
        user="me",
        uid=501,
        home=str(home),
        home_mode="drwx------",
    )


def test_listeners_parse_tcp_ports_and_unix_socket_paths_with_modes(tmp_path: Path):
    sock = tmp_path / "control.sock"
    sock.write_bytes(b"")
    sock.chmod(0o600)
    system = system_with("", LSOF_TCP, lsof_unix(sock))
    found = listeners(system, [59569, 47165])
    assert found == [
        (59569, Listener("tcp", "127.0.0.1:49374")),
        (47165, Listener("unix", str(sock), "600")),
    ]


def test_daemons_are_detached_or_listening_processes_with_observed_notes(tmp_path: Path):
    system = system_with(PS, "", lsof_unix(tmp_path / "missing.sock"))
    ctx = Context(home=tmp_path, system=system, now=time.time())
    report = ToolReport(
        name="codex",
        display_name="Codex CLI",
        installed=True,
        binaries=[BinaryInfo("/usr/local/bin/codex", "/opt/codex/bin/codex", version="0.162.0")],
    )
    report.processes = processes(system, r"(^|/)codex(\s|$)")
    found = daemons.collect(ctx, report)
    assert [d.pid for d in found] == [47165, 49573]
    daemon, updater = found
    assert daemon.detached and daemon.days >= 1
    assert daemon.listeners == [Listener("unix", str(tmp_path / "missing.sock"))]
    assert daemon.notes == [
        "runs /Users/me/.codex/packages/app-server-daemon/releases/0.162.0-aarch64-apple-darwin/"
        "bin/codex, not the binary on PATH"
    ]
    assert "version 0.161.0 (installed: 0.162.0)" in updater.notes
    assert "self-update loop" in updater.notes


def test_rule_names_each_daemon_and_offers_validated_codex_fixes(tmp_path: Path):
    report = ToolReport(name="codex", display_name="Codex CLI", installed=True)
    report.daemons = [
        Daemon(
            pid=47165,
            ppid=1,
            started="Fri Oct  9 10:25:32 2026",
            command="/x/bin/codex app-server --listen unix:// --managed-daemon",
            binary="/x/bin/codex",
            detached=True,
            days=3,
            listeners=[Listener("unix", "/tmp/codex-daemon-501/abcdefghijklmnopqrstuvwxyz", "600")],
            notes=["runs /x/bin/codex, not the binary on PATH"],
        ),
        Daemon(
            pid=7,
            ppid=400,
            started="",
            command="/x/bin/codex app-server --listen stdio://",
            binary="/x/bin/codex",
            detached=False,
            days=0,
        ),
    ]
    ctx = rules.RuleContext(host=host(tmp_path), platform="darwin", home=tmp_path)
    [found] = rules.rule_daemons(report, ctx)
    assert found.statement == (
        "Codex CLI keeps 1 background process running outside any session (started by "
        "launchd): pid 47165 "
        "`app-server --listen unix:// --managed-daemon` (3 days, launchd; unix "
        "/tmp/codex-daemon-501/abcdefghijkl… mode 600; binary /x/bin/codex, not the one on PATH)."
    )
    assert found.fix is not None
    assert [c.text for c in found.fix.commands] == [
        "codex app-server daemon stop",
        "pkill -f 'app-server daemon pid-update-loop'",
        "codex features disable daemon_auto_start",
    ]


def test_a_session_child_that_listens_is_named_with_its_session_and_never_killed(
    tmp_path: Path,
):
    report = ToolReport(name="opencode", display_name="OpenCode", installed=True)
    report.daemons = [
        Daemon(
            pid=50615,
            ppid=50614,
            started="Fri Oct 16 14:37:00 2026",
            command="/x/opencode.exe serve --service",
            binary="/x/opencode.exe",
            detached=False,
            days=0,
            listeners=[Listener("tcp", "127.0.0.1:49374")],
        )
    ]
    ctx = rules.RuleContext(host=host(tmp_path), platform="darwin", home=tmp_path)
    [found] = rules.rule_daemons(report, ctx)
    assert found.statement == (
        "OpenCode sessions accept connections: pid 50615 `serve --service`, started by "
        "session pid 50614, on tcp 127.0.0.1:49374."
    )
    assert "outside any session" not in found.statement
    assert found.fix is not None
    assert [c.text for c in found.fix.commands] == [
        "Stop pid 50615 (started by session pid 50614) when you no longer need it"
    ]


def test_session_sockets_readable_only_by_the_user_are_not_an_exposure(tmp_path: Path):
    report = ToolReport(name="claude", display_name="Claude Code", installed=True)
    report.daemons = [
        Daemon(
            pid=3977,
            ppid=33539,
            started="",
            command="claude",
            binary="claude",
            detached=False,
            days=5,
            listeners=[Listener("unix", "/tmp/cc-socks/3977.sock", "600")],
        )
    ]
    ctx = rules.RuleContext(host=host(tmp_path), platform="darwin", home=tmp_path)
    assert rules.rule_daemons(report, ctx) == []
    report.daemons[0].listeners = [Listener("tcp", "127.0.0.1:5000")]
    assert len(rules.rule_daemons(report, ctx)) == 1


def test_version_note_ignores_the_node_version_in_a_launcher_path():
    report = ToolReport(
        name="opencode",
        display_name="OpenCode",
        installed=True,
        binaries=[BinaryInfo("/opt/opencode", "/opt/opencode", version="1.4.6")],
    )
    proc = ProcessInfo(1, "", "/Users/me/.nvm/versions/node/v24.14.1/bin/opencode.exe serve", 1)
    assert daemons._notes(
        proc, "/Users/me/.nvm/versions/node/v24.14.1/bin/opencode.exe", report
    ) == ["runs /Users/me/.nvm/versions/node/v24.14.1/bin/opencode.exe, not the binary on PATH"]
