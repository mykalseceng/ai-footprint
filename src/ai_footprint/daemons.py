"""Tool processes that outlive a session or accept connections, with what they listen on.

A daemon here is any process of the tool that launchd started (no terminal session owns
it) or that accepts connections on a TCP port or a unix socket. Everything reported is read
from ``ps`` and ``lsof``: start time, parent, command line, listening addresses and socket
file modes. Notes state observed facts only: the binary differs from the one on PATH, the
command line names a self-update loop, or the version in the path differs.
"""

import datetime
import re

from ai_footprint.collectors.common import Context
from ai_footprint.host import listeners, started_at
from ai_footprint.model import Daemon, ProcessInfo, ToolReport
from ai_footprint.surface import plural, short_path

VERSION = re.compile(r"(?<![\dv.])\d+\.\d+\.\d+")
UPDATE_LOOP = "pid-update-loop"
MAX_COMMAND = 200


def _binary(command: str) -> str:
    """The program a command line runs: its first word, allowing for a quoted path."""
    if command.startswith('"'):
        return command[1:].split('"', 1)[0]
    words = command.split()
    while len(words) > 1 and words[0].endswith("\\"):
        words = [f"{words[0][:-1]} {words[1]}", *words[2:]]
    return words[0] if words else ""


def _off_path(binary: str, report: ToolReport) -> bool:
    installed = {b.resolved for b in report.binaries}
    return bool(installed) and binary.startswith("/") and binary not in installed


def _notes(proc: ProcessInfo, binary: str, report: ToolReport) -> list[str]:
    """Observed facts; the off-PATH note, when there is one, always comes first."""
    notes = []
    if _off_path(binary, report):
        notes.append(f"runs {binary}, not the binary on PATH")
    version = VERSION.search(binary)
    current = report.versions()
    if version and current and version.group(0) not in current:
        notes.append(f"version {version.group(0)} (installed: {', '.join(current)})")
    if UPDATE_LOOP in proc.command:
        notes.append("self-update loop")
    return notes


def collect(ctx: Context, report: ToolReport) -> list[Daemon]:
    """Daemons among the tool's processes, newest listeners attached."""
    if not report.processes:
        return []
    by_pid: dict[int, list] = {}
    for pid, listener in listeners(ctx.system, [p.pid for p in report.processes]):
        by_pid.setdefault(pid, []).append(listener)
    now = datetime.datetime.now()
    out = []
    for proc in report.processes:
        detached = proc.ppid == 1
        if not detached and proc.pid not in by_pid:
            continue
        started = started_at(proc)
        binary = _binary(proc.command)
        out.append(
            Daemon(
                pid=proc.pid,
                ppid=proc.ppid,
                started=proc.started,
                command=proc.command[:MAX_COMMAND],
                binary=binary,
                detached=detached,
                days=(now - started).days if started else 0,
                listeners=by_pid.get(proc.pid, []),
                notes=_notes(proc, binary, report),
                off_path=_off_path(binary, report),
            )
        )
    return out


def describe(daemon: Daemon, home: str) -> tuple[str, list[str], list[str]]:
    """(what it runs, where it listens, observed notes), each short enough for a table cell."""
    what = daemon.command.removeprefix(daemon.binary).strip() or daemon.binary.rsplit("/", 1)[-1]
    listens = [
        f"{ln.kind} {short_path(ln.address, home)}" + (f" mode {ln.mode}" if ln.mode else "")
        for ln in daemon.listeners
    ]
    notes = list(daemon.notes)
    if daemon.off_path:
        notes[0] = f"binary {short_path(daemon.binary, home)}, not the one on PATH"
    return what[:60] + ("…" if len(what) > 60 else ""), listens, notes


def running(daemon: Daemon) -> str:
    """``3 days, launchd`` or ``0 days, session child``."""
    return f"{plural(daemon.days, 'day')}, {'launchd' if daemon.detached else 'session child'}"
