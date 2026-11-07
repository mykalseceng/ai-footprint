"""Tool processes that outlive a session or accept connections, with what they listen on.

A daemon here is any process of the tool that launchd started (no terminal session owns
it) or that accepts connections on a TCP port or a unix socket. Everything reported is read
from ``ps`` and ``lsof``: start time, parent, command line, listening addresses and socket
file modes. Notes state observed facts only: the binary differs from the one on PATH, the
command line names a self-update loop, or the version in the path differs.
"""

import datetime
import re
from pathlib import Path

from ai_footprint.harnesses.common import Context
from ai_footprint.host import listeners, readable_command, started_at
from ai_footprint.model import Daemon, ProcessInfo, ToolReport
from ai_footprint.text import plural, short_path

VERSION = re.compile(r"(?<![\dv.])\d+\.\d+\.\d+")
UPDATE_LOOP = "pid-update-loop"
MAX_COMMAND = 200


MAX_PATH_WORDS = 8


def _binary(command: str) -> str:
    """The program a command line runs: its first word, allowing for a quoted path.

    ``ps`` does not quote paths, so for an absolute path the longest run of leading words
    that names an existing file is taken (``/Applications/My App.app/...``).
    """
    if command.startswith('"'):
        return command[1:].split('"', 1)[0]
    if command.startswith("/"):
        parts = command.split(" ")
        for count in range(min(len(parts), MAX_PATH_WORDS), 1, -1):
            candidate = " ".join(parts[:count])
            if Path(candidate).is_file():
                return candidate
    words = command.split()
    while len(words) > 1 and words[0].endswith("\\"):
        words = [f"{words[0][:-1]} {words[1]}", *words[2:]]
    return words[0] if words else ""


def _off_path(binary: str, report: ToolReport) -> bool:
    """A program that is neither an installed binary nor inside an installed app bundle."""
    installed = {b.resolved for b in report.binaries} | {b.path for b in report.binaries}
    bundles = tuple(
        b.path.split(".app/", 1)[0] + ".app/" for b in report.binaries if ".app/" in b.path
    )
    return (
        bool(installed)
        and binary.startswith("/")
        and binary not in installed
        and not binary.startswith(bundles or ("\0",))
    )


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


def _app_executables(report: ToolReport) -> tuple[str, ...]:
    """Main executables of the tool's installed app bundles.

    macOS starts every app through launchd, so the running app itself has no session
    parent; it is the app, not a process left behind.
    """
    return tuple(b.path for b in report.binaries if ".app/Contents/MacOS/" in b.path)


def collect(ctx: Context, report: ToolReport) -> list[Daemon]:
    """Daemons among the tool's processes, newest listeners attached."""
    if not report.processes:
        return []
    by_pid: dict[int, list] = {}
    for pid, listener in listeners(ctx.system, [p.pid for p in report.processes]):
        by_pid.setdefault(pid, []).append(listener)
    now = datetime.datetime.now()
    out = []
    apps = _app_executables(report)
    for proc in report.processes:
        detached = proc.ppid == 1 and not proc.command.startswith(apps)
        if not detached and proc.pid not in by_pid:
            continue
        started = started_at(proc)
        binary = _binary(proc.command)
        out.append(
            Daemon(
                pid=proc.pid,
                ppid=proc.ppid,
                started=proc.started,
                command=readable_command(proc.command, MAX_COMMAND),
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
    name = daemon.binary.rsplit("/", 1)[-1]
    what = f"{name} {daemon.command.removeprefix(daemon.binary).strip()}".strip()
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
