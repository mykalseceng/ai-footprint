"""The Network page: where each tool connected when started idle, and what it only names.

Observed rows come from ``--capture`` only. Hosts the installed binary names but that no
packet in the capture reached are listed apart, so a name in a binary is never shown as a
connection.
"""

import dataclasses
from typing import Any

from ai_footprint import surface
from ai_footprint.fsinfo import tilde
from ai_footprint.model import AuditReport, Connection, ToolCapture, ToolReport

HOW = (
    "Run ai-footprint --capture to record it: each tool starts idle, with no prompt, in an "
    "empty folder for 60 seconds while a sudo packet capture records every packet its "
    "processes send or receive."
)

UNATTRIBUTED = (
    "Processes named like a tool's helpers (node, bun, npm, git and similar) that sent packets "
    "during a tool's window but were never seen in its process tree: a short-lived child the "
    "sampling missed, or unrelated."
)


def captured(audit: AuditReport, tool: str) -> ToolCapture | None:
    """The capture of one tool, when the run has one."""
    if audit.network is None:
        return None
    return next((t for t in audit.network.tools if t.tool == tool), None)


def _reached(host: str, connections: list[Connection]) -> bool:
    return any(c.host == host or c.host.endswith(f".{host}") for c in connections)


def _summary(tool: ToolReport, found: ToolCapture | None) -> str:
    if found is None:
        return f"{tool.display_name} was not captured. {HOW}"
    hosts = list(dict.fromkeys(c.host for c in found.connections))
    if not hosts:
        return (
            f"Started idle for {found.seconds:g}s with no prompt, {found.display_name} "
            f"{found.version} exchanged no packets with any host off this machine."
        )
    shown = surface.join(hosts[:6] + ([f"{len(hosts) - 6} more"] if len(hosts) > 6 else []))
    return (
        f"Started idle for {found.seconds:g}s with no prompt, {found.display_name} "
        f"{found.version} reached {surface.plural(len(hosts), 'host')}: {shown}."
    )


def _tool(audit: AuditReport, tool: ToolReport) -> dict[str, Any]:
    found = captured(audit, tool.name)
    connections = found.connections if found else []
    named = list(dict.fromkeys(e.host for e in tool.endpoints if e.source == "binary"))
    purposes = {e.host: e.purpose for e in tool.endpoints if e.source == "binary"}
    return {
        "summary": _summary(tool, found),
        "captured": found is not None,
        "command": [tilde(part, audit.host.home) for part in found.command] if found else [],
        "observed": [dataclasses.asdict(c) for c in connections],
        "lookups": found.lookups if found else [],
        "unobserved": [
            {"host": host, "purpose": purposes[host]}
            for host in named
            if not _reached(host, connections)
        ],
        "switches": found.switches if found else [],
        "stopped": found.stopped if found else [],
        "local_packets": found.local_packets if found else 0,
    }


def view(audit: AuditReport) -> dict[str, Any]:
    """Everything the Network page shows, per installed tool."""
    capture = audit.network
    return {
        "method": capture.method if capture else "",
        "started_at": capture.started_at if capture else "",
        "capture_file": tilde(capture.capture_file, audit.host.home) if capture else "",
        "how": HOW,
        "tools": {t.name: _tool(audit, t) for t in audit.tools if t.installed},
        "unattributed": [dataclasses.asdict(c) for c in capture.unattributed] if capture else [],
        "unattributed_note": UNATTRIBUTED,
    }
