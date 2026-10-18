"""The capture run: process-tree tracking, idle launches, reading the file back, saving."""

import json
import os
import time
from pathlib import Path

import pytest

from ai_footprint import capture, network
from ai_footprint.model import BinaryInfo, ToolPresence
from ai_footprint.system import ProbeResult, System
from tests.conftest import FakeSystem
from tests.test_network import (
    LOCAL,
    REMOTE,
    client_hello,
    frame,
    meta_line,
    pcapng,
    tcp,
)


def ps_table(rows: list[tuple[int, int]]) -> FakeSystem:
    system = FakeSystem()
    text = "\n".join(f"{pid} {parent}" for pid, parent in rows)
    system.responders.append(
        lambda argv: ProbeResult(0, text, "") if argv[0].endswith("/ps") else None
    )
    return system


def test_tree_follows_every_descendant():
    system = ps_table([(10, 1), (11, 10), (12, 11), (13, 1), (14, 13)])
    assert capture._tree(system, {10}) == {10, 11, 12}
    assert system.executed == []


def test_analyse_reads_the_file_and_tcpdumps_metadata(tmp_path: Path):
    path = tmp_path / "c.pcapng"
    path.write_bytes(pcapng([(5.0, frame(LOCAL, REMOTE, tcp(50000, 443, client_hello("x.dev"))))]))
    system = FakeSystem()
    system.responders.append(
        lambda argv: (
            ProbeResult(0, meta_line(5.0, "claude", 7, "out"), "")
            if argv[0].endswith("tcpdump")
            else None
        )
    )
    window = network.Window("claude", "Claude Code", "2.1.302", ["/bin/claude"], 4.0, 64.0, {7})
    found = capture.analyse(system, path, [window], "2026-10-17T20:00:00+00:00")
    [tool] = found.tools
    assert [(c.host, c.first_second) for c in tool.connections] == [("x.dev", 1.0)]
    assert system.executed[-1].argv[1:4] == ["-r", str(path), "-n"]


def test_analyse_fails_clearly_when_metadata_does_not_line_up(tmp_path: Path):
    path = tmp_path / "c.pcapng"
    path.write_bytes(pcapng([(5.0, frame(LOCAL, REMOTE, tcp(1, 443)))]))
    with pytest.raises(capture.CaptureError, match="1 packets in the file, 0 lines"):
        capture.analyse(FakeSystem(), path, [], "")


def test_saved_capture_loads_back_and_bad_files_are_refused(tmp_path: Path):
    path = tmp_path / "c.pcapng"
    path.write_bytes(pcapng([(5.0, frame(LOCAL, REMOTE, tcp(50000, 443, client_hello("x.dev"))))]))
    system = FakeSystem()
    system.responders.append(lambda _argv: ProbeResult(0, meta_line(5.0, "pi", 3, "out"), ""))
    window = network.Window("pi", "pi", "1.2.0", ["/bin/pi"], 4.0, 64.0, {3}, ["DISABLE_X"])
    found = capture.analyse(system, path, [window], "t")
    saved = tmp_path / "c.json"
    saved.write_text(capture.dumps(found))
    assert capture.load(saved) == found
    saved.write_text('{"method": "x"}')
    with pytest.raises(capture.CaptureError, match="not a capture saved by --capture"):
        capture.load(saved)


def test_capture_stops_when_sudo_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    system = FakeSystem()
    monkeypatch.setattr(system, "interactive", lambda _name, _args: 1)
    with pytest.raises(capture.CaptureError, match="sudo was not authorised"):
        capture.record(system, [], tmp_path / "c.pcapng")


def test_idle_launch_tracks_children_and_stops_what_it_left_running(tmp_path: Path):
    marker = tmp_path / "child.pid"
    tool = tmp_path / "fake-tool"
    detach = "perl -MPOSIX -e 'setsid(); sleep 300'"
    tool.write_text(f"#!/bin/sh\n{detach} &\necho $! > {marker}\nsleep 300\n")
    tool.chmod(0o755)
    presence = ToolPresence(
        "fake", "Fake Tool", installed=True, binaries=[BinaryInfo(str(tool), str(tool), "1.0")]
    )
    system = System(verify_signatures=False, env={**os.environ, "DISABLE_TELEMETRY": "1"})
    window = capture.launch(system, presence, seconds=1.0)
    child = int(marker.read_text())
    assert child in window.pids
    assert any(f"(pid {child})" in entry for entry in window.stopped)
    assert "DISABLE_TELEMETRY" in window.switches
    assert window.end - window.start >= 1.0
    time.sleep(0.3)
    for pid in window.pids:
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)
    purposes = [r.purpose for r in system.executed]
    assert "Launch idle with no prompt while the packet capture runs" in purposes
    assert any(p.startswith("Track Fake Tool's process tree") for p in purposes)


def test_windows_round_trip_so_a_capture_can_be_analysed_again(tmp_path: Path):
    path = tmp_path / "c.pcapng"
    window = network.Window("pi", "pi", "1.2.0", ["/bin/pi"], 4.0, 64.0, {3, 5}, ["X"], ["y"])
    capture._write_private(capture.windows_path(path), json.dumps([capture._window_json(window)]))
    assert capture.load_windows(path) == [window]
    assert oct(capture.windows_path(path).stat().st_mode & 0o777) == "0o600"


def test_capture_process_stays_in_the_terminal_session_sudo_authorised(
    monkeypatch: pytest.MonkeyPatch,
):
    seen: dict = {}

    def fake_popen(argv, **kwargs):
        seen.update(kwargs, argv=argv)

    monkeypatch.setattr("ai_footprint.system.subprocess.Popen", fake_popen)
    FakeSystem().start("sudo", ["-n", "/usr/sbin/tcpdump"])
    assert seen["argv"][:2] == ["/usr/bin/sudo", "-n"]
    assert not seen.get("start_new_session")
