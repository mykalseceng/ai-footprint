"""Facts about the machine: other accounts, PATH writability, AI-tool processes, sockets."""

import datetime
import grp
import os
import platform
import re
import stat
from dataclasses import dataclass
from pathlib import Path

from ai_footprint.fsinfo import mode_string, owner_name
from ai_footprint.model import HostReport, Listener, PathEntry, ProcessInfo
from ai_footprint.system import CommandRefusedError, System

SYSTEM_DIRS = ("/usr/bin", "/bin", "/usr/sbin", "/sbin")


@dataclass
class Socket:
    """One TCP socket owned by a process."""

    pid: int
    command: str
    local: str
    remote: str
    state: str


def collect_host(system: System, home: Path) -> HostReport:
    """Gather OS, account and PATH facts."""
    uname = platform.uname()
    user = system.env.get("USER") or owner_name(os.getuid())
    others = other_users(system, user)
    return HostReport(
        os=_os_name(system.platform),
        kernel=f"{uname.system} {uname.release}",
        arch=uname.machine,
        hostname=uname.node,
        user=user,
        uid=os.getuid(),
        home=str(home),
        home_mode=mode_string(home.stat().st_mode) if home.exists() else "",
        other_users=others,
        other_user_groups={name: user_groups(system, name) for name in others},
        path_entries=path_entries(system.env.get("PATH", "")),
    )


def _os_name(plat: str) -> str:
    if plat == "darwin":
        return f"macOS {platform.mac_ver()[0]}".strip()
    return platform.platform()


def other_users(system: System, current: str) -> list[str]:
    """Interactive local accounts other than ``current``."""
    if system.platform == "darwin" and system.has_probe("dscl"):
        result = system.run("dscl", [".", "-list", "/Users", "UniqueID"])
        names = []
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1].isdigit() and int(parts[1]) >= 500:
                names.append(parts[0])
        return sorted(n for n in names if n != current and not n.startswith("_"))
    return _passwd_users(current)


def _passwd_users(current: str) -> list[str]:
    names = []
    try:
        lines = Path("/etc/passwd").read_text().splitlines()
    except OSError:
        return []
    for line in lines:
        fields = line.split(":")
        if len(fields) < 7 or not fields[2].isdigit():
            continue
        shell_ok = not fields[6].endswith(("nologin", "false"))
        if int(fields[2]) >= 1000 and shell_ok and fields[0] != current:
            names.append(fields[0])
    return sorted(names)


def user_groups(system: System, name: str) -> list[str]:
    """Group names for a local account."""
    if not system.has_probe("id"):
        return []
    result = system.run("id", ["-Gn", name])
    return result.stdout.split() if result.returncode == 0 else []


def path_entries(path_value: str) -> list[PathEntry]:
    """Describe each PATH directory: owner, group, and whether others can write to it."""
    entries = []
    for index, directory in enumerate(path_value.split(os.pathsep), start=1):
        if not directory:
            continue
        entry = PathEntry(index=index, path=directory, exists=False)
        try:
            info = Path(directory).stat()
        except OSError:
            entries.append(entry)
            continue
        entry.exists = True
        entry.owner = owner_name(info.st_uid)
        entry.group = _group_name(info.st_gid)
        entry.mode = mode_string(info.st_mode)
        sticky = bool(info.st_mode & stat.S_ISVTX)
        entry.group_writable = bool(info.st_mode & stat.S_IWGRP) and not sticky
        entry.other_writable = bool(info.st_mode & stat.S_IWOTH) and not sticky
        entries.append(entry)
    return entries


def _group_name(gid: int) -> str:
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return str(gid)


def first_system_index(entries: list[PathEntry]) -> int:
    """PATH index of the first system binary directory (``/usr/bin`` etc.)."""
    for entry in entries:
        if entry.path.rstrip("/") in SYSTEM_DIRS:
            return entry.index
    return len(entries) + 1


PS_LINE = re.compile(r"\s*(\d+)\s+(\d+)\s+(\w{3}\s+\w{3}\s+\d+\s+[\d:]+\s+\d{4})\s+(.*)")


def all_processes(system: System) -> list[ProcessInfo]:
    """Every process with pid, parent pid, start time and command line."""
    if not system.has_probe("ps"):
        return []
    result = system.run("ps", ["-axww", "-o", "pid=,ppid=,lstart=,command="])
    found = []
    for line in result.stdout.splitlines():
        match = PS_LINE.match(line)
        if match:
            found.append(
                ProcessInfo(
                    int(match.group(1)),
                    match.group(3),
                    match.group(4)[:300],
                    ppid=int(match.group(2)),
                )
            )
    return found


def processes(system: System, pattern: str) -> list[ProcessInfo]:
    """Running processes whose command line matches ``pattern`` (a regex)."""
    regex = re.compile(pattern)
    return [p for p in all_processes(system) if regex.search(p.command)]


def started_at(proc: ProcessInfo) -> datetime.datetime | None:
    """The process start time parsed from ``ps`` ``lstart`` output (local wall clock)."""
    try:
        return datetime.datetime.strptime(" ".join(proc.started.split()), "%a %b %d %H:%M:%S %Y")
    except ValueError:
        return None


def listeners(system: System, pids: list[int]) -> list[tuple[int, Listener]]:
    """(pid, listener) for every TCP port and unix socket path the processes accept on."""
    if not pids or not system.has_probe("lsof"):
        return []
    targets = ",".join(str(pid) for pid in pids)
    found: list[tuple[int, Listener]] = []
    try:
        tcp = system.run("lsof", ["-nP", "-a", "-iTCP", "-sTCP:LISTEN", "-p", targets])
        unix = system.run("lsof", ["-nP", "-a", "-U", "-p", targets])
    except CommandRefusedError:
        return []
    for line in tcp.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 9 and parts[1].isdigit():
            found.append((int(parts[1]), Listener("tcp", parts[8])))
    for line in unix.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 8 and parts[1].isdigit() and parts[-1].startswith("/"):
            path = Path(parts[-1])
            mode = mode_string(path.stat().st_mode) if path.exists() else ""
            found.append((int(parts[1]), Listener("unix", parts[-1], mode)))
    return found


def sockets(system: System, pids: list[int]) -> list[Socket]:
    """TCP sockets owned by the given processes."""
    if not pids or not system.has_probe("lsof"):
        return []
    try:
        result = system.run(
            "lsof", ["-nP", "-a", "-iTCP", "-p", ",".join(str(pid) for pid in pids)]
        )
    except CommandRefusedError:
        return []
    found = []
    for line in result.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9 or not parts[1].isdigit():
            continue
        name = parts[8]
        state = parts[9].strip("()") if len(parts) > 9 else ""
        local, _, remote = name.partition("->")
        found.append(Socket(int(parts[1]), parts[0], local, remote, state))
    return found
