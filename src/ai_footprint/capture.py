"""Record where each tool connects when launched idle, with no prompt (``--capture``).

One packet capture covers the whole run: ``sudo tcpdump -i pktap,all`` records every packet
with the process the kernel says owns it, then drops root (``-Z``) so the file belongs to
you. Each selected tool is then launched in turn, as you would start it, in a pseudo-
terminal in an empty temporary folder, left idle for ``SECONDS`` and quit. Its process tree
is sampled with ``ps`` while it runs, so packets from its children count too. Processes it
started that are still running afterwards are stopped and listed.

The tools run with your environment, configuration and logins: that is what "by default"
means here. They may write their own state while they run, as they do whenever you start
them.
"""

import contextlib
import dataclasses
import datetime
import json
import os
import re
import signal
import subprocess
import tempfile
import threading
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ai_footprint import network, pcap
from ai_footprint.model import Connection, NetworkCapture, ToolCapture, ToolPresence
from ai_footprint.system import System

SECONDS = 60.0
SAMPLE_EVERY = 0.2
SETTLE_SECONDS = 3.0
STARTUP_WAIT = 15.0
METHOD = "tcpdump -i pktap,all, with the kernel's per-packet process metadata"
SWITCH = re.compile(r"DISABLE|TELEMETRY|OFFLINE|_PROXY$|^NO_PROXY$", re.IGNORECASE)
"""Environment variable names recorded with each launch: off-switches and proxies."""


class CaptureError(RuntimeError):
    """The capture could not start, or its file could not be read back."""


def _tree(system: System, roots: set[int]) -> set[int]:
    """``roots`` and every process descended from them right now."""
    table = system.run("ps", ["-axo", "pid=,ppid="], log=False).stdout
    parents = {}
    for line in table.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[0].isdigit() and fields[1].isdigit():
            parents[int(fields[0])] = int(fields[1])
    found = set(roots)
    grew = True
    while grew:
        children = {pid for pid, parent in parents.items() if parent in found} - found
        found |= children
        grew = bool(children)
    return found


def _drain(controller: int) -> threading.Thread:
    """Read and discard terminal output so the tool never blocks writing to it."""

    def read() -> None:
        with contextlib.suppress(OSError):
            while os.read(controller, 65536):
                pass

    thread = threading.Thread(target=read, daemon=True)
    thread.start()
    return thread


def _quit(proc: subprocess.Popen[bytes], controller: int) -> None:
    """Ctrl-C twice, then SIGTERM and SIGKILL to the tool's process group."""
    for _ in range(2):
        with contextlib.suppress(OSError):
            os.write(controller, b"\x03")
        time.sleep(0.5)
    for sig, wait in ((signal.SIGTERM, 3.0), (signal.SIGKILL, 2.0)):
        if proc.poll() is not None:
            return
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(proc.pid, sig)
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=wait)


def _stop_leftovers(system: System, pids: set[int], before: set[int]) -> list[str]:
    """Stop processes the launch started that are still running; name each one."""
    table = system.run("ps", ["-axo", "pid=,comm="], log=False).stdout
    names = {}
    for line in table.splitlines():
        fields = line.strip().split(None, 1)
        if len(fields) == 2 and fields[0].isdigit():
            names[int(fields[0])] = fields[1].rsplit("/", 1)[-1]
    alive = {pid for pid in pids - before if pid in names}
    for pid in sorted(alive):
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.kill(pid, signal.SIGTERM)
    return [f"{names[pid]} (pid {pid})" for pid in sorted(alive)]


def _environment(base: Mapping[str, str]) -> dict[str, str]:
    env = dict(base)
    env.setdefault("TERM", "xterm-256color")
    return env


def launch(system: System, presence: ToolPresence, seconds: float) -> network.Window:
    """Run one tool idle under the capture and return its window and process tree."""
    binary = presence.binaries[0]
    before = _tree(system, {1})
    env = _environment(system.env)
    with tempfile.TemporaryDirectory(prefix="ai-footprint-capture-") as cwd:
        start = time.time()
        proc, controller = system.launch_idle(binary.path, cwd=cwd, env=env)
        reader = _drain(controller)
        pids, samples = {proc.pid}, 0
        while time.time() - start < seconds and proc.poll() is None:
            pids |= _tree(system, pids)
            samples += 1
            time.sleep(SAMPLE_EVERY)
        pids |= _tree(system, pids)
        _quit(proc, controller)
        end = time.time()
        os.close(controller)
        reader.join(timeout=1)
    system.note(
        "ps",
        ["-axo", "pid=,ppid="],
        f"Track {presence.display_name}'s process tree during the capture "
        f"(sampled {samples} times)",
    )
    return network.Window(
        tool=presence.name,
        display_name=presence.display_name,
        version=binary.version,
        command=[binary.path],
        start=start,
        end=end,
        pids=pids,
        switches=sorted(k for k in env if SWITCH.search(k)),
        stopped=_stop_leftovers(system, pids, before),
    )


def _started(proc: subprocess.Popen[bytes], path: Path) -> None:
    """Wait for tcpdump to open its file, or fail with what it printed."""
    deadline = time.time() + STARTUP_WAIT
    while time.time() < deadline:
        if proc.poll() is not None:
            stderr = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
            raise CaptureError(f"tcpdump exited with status {proc.returncode}: {stderr.strip()}")
        if path.is_file() and path.stat().st_size > 0:
            return
        time.sleep(0.2)
    raise CaptureError(f"tcpdump did not start writing {path} within {STARTUP_WAIT:.0f}s")


def _stop(system: System, proc: subprocess.Popen[bytes]) -> None:
    """Stop tcpdump. After ``-Z`` it runs as you, so it can be signalled directly."""
    table = system.run("ps", ["-axo", "pid=,ppid="], log=False).stdout
    children = [
        int(fields[0])
        for fields in (line.split() for line in table.splitlines())
        if len(fields) == 2 and fields[1] == str(proc.pid)
    ]
    for pid in children:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.kill(pid, signal.SIGINT)
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired as exc:
        raise CaptureError(
            "tcpdump did not stop; it exits on its own when its time limit is reached"
        ) from exc


def record(
    system: System, presences: list[ToolPresence], path: Path, seconds: float = SECONDS
) -> NetworkCapture:
    """Capture packets while each tool runs idle, then attribute them.

    Raises:
        CaptureError: sudo was refused, tcpdump could not start, or the file is unreadable.
    """
    if system.interactive("sudo", ["-v"]) != 0:
        raise CaptureError("sudo was not authorised; the capture needs your admin password")
    path.unlink(missing_ok=True)
    limit = int(seconds * len(presences) + 120)
    user = system.env.get("USER") or os.getlogin()
    proc = system.start(
        "sudo",
        [
            "-n",
            system.probe_path("tcpdump"),
            "-i",
            "pktap,all",
            "-Z",
            user,
            "-U",
            "-G",
            str(limit),
            "-W",
            "1",
            "-w",
            str(path),
        ],
    )
    _started(proc, path)
    started_at = datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds")
    windows = []
    try:
        for presence in presences:
            windows.append(launch(system, presence, seconds))
            time.sleep(SETTLE_SECONDS)
    finally:
        _stop(system, proc)
    path.chmod(0o600)
    _write_private(windows_path(path), json.dumps([_window_json(w) for w in windows], indent=2))
    return analyse(system, path, windows, started_at)


def windows_path(path: Path) -> Path:
    """Where the launch windows are kept, so the file can be analysed again without sudo."""
    return path.with_suffix(".windows.json")


def _window_json(window: network.Window) -> dict[str, Any]:
    return {**dataclasses.asdict(window), "pids": sorted(window.pids)}


def load_windows(path: Path) -> list[network.Window]:
    """Launch windows saved by ``record``."""
    rows: list[dict[str, Any]] = json.loads(windows_path(path).read_text())
    return [
        network.Window(
            tool=row["tool"],
            display_name=row["display_name"],
            version=row["version"],
            command=list(row["command"]),
            start=float(row["start"]),
            end=float(row["end"]),
            pids=set(row["pids"]),
            switches=list(row["switches"]),
            stopped=list(row["stopped"]),
        )
        for row in rows
    ]


def _write_private(path: Path, text: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)


def analyse(
    system: System, path: Path, windows: list[network.Window], started_at: str
) -> NetworkCapture:
    """Attribute every packet in ``path`` to the tool whose processes sent or received it.

    Raises:
        CaptureError: The file cannot be parsed, or tcpdump's metadata does not line up.
    """
    try:
        raw = pcap.read_packets(path)
        text = system.run("tcpdump", ["-r", str(path), "-n", "-tt", "-q", "-k", "NPD"], timeout=600)
        meta = network.align(raw, network.parse_metadata(text.stdout))
    except (pcap.PcapError, network.AlignmentError, OSError) as exc:
        raise CaptureError(f"could not read the capture {path}: {exc}") from exc
    packets = [(p, m) for r, m in zip(raw, meta, strict=True) if (p := pcap.decode(r))]
    names = network.Names(p for p, _m in packets)
    return NetworkCapture(
        method=METHOD,
        started_at=started_at,
        capture_file=str(path),
        tools=[network.tool_capture(w, packets, names) for w in windows],
        unattributed=network.unattributed(windows, packets, names),
    )


def dumps(capture: NetworkCapture) -> str:
    """The capture as JSON, for ``--network`` to load later."""
    return json.dumps(dataclasses.asdict(capture), indent=2)


def _tool(data: dict[str, Any]) -> ToolCapture:
    fields = {f.name for f in dataclasses.fields(ToolCapture)} - {"connections"}
    tool = ToolCapture(**{k: v for k, v in data.items() if k in fields})
    tool.connections = [Connection(**c) for c in data["connections"]]
    return tool


def load(path: Path) -> NetworkCapture:
    """A capture saved by ``--capture``.

    Raises:
        CaptureError: The file is missing or is not a saved capture.
    """
    try:
        data: dict[str, Any] = json.loads(path.read_text())
        return NetworkCapture(
            method=data["method"],
            started_at=data["started_at"],
            capture_file=data["capture_file"],
            tools=[_tool(t) for t in data["tools"]],
            unattributed=[Connection(**c) for c in data["unattributed"]],
        )
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise CaptureError(f"{path} is not a capture saved by --capture: {exc}") from exc
