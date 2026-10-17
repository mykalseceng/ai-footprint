"""Every number the dashboard and the report show, each with a statement of what was counted.

A figure is computed here once, from the audit, and shown as is: no renderer adds, rounds or
relabels it. ``figurecheck`` recomputes each figure independently from the run's document,
so a wrong sum, a double count or a stale label fails ``--validate``.

Sums never count the same bytes twice: when one listed location sits inside another, only
the outer one is added. A count that is distinct only within each tool says so.
"""

from collections import Counter
from dataclasses import dataclass
from typing import Any

from ai_footprint import keys, rules, surface
from ai_footprint.fsinfo import human_size
from ai_footprint.model import Artifact, AuditReport, Category, Lens, ToolReport
from ai_footprint.rules import Checklist

TOOL_RUN_PURPOSES = ("Confirm tool version", "Confirm subcommand exists")
KIND_NAMES = {
    "mcp": "MCP server",
    "connector": "claude.ai connector",
    "plugin": "plugin",
    "skill": "skill",
    "hook": "hook",
    "native-host": "browser native host",
    "statusline": "status line",
}


@dataclass
class Figure:
    """One number as shown, with exactly what it counts.

    Attributes:
        id: Stable key, also used to find the figure in the rendered page.
        label: Tile heading.
        value: The number, or the state for a figure that is a state; None when not measured.
        display: ``value`` as printed.
        detail: What was counted and from where, in one sentence fragment.
    """

    id: str
    label: str
    value: int | str | None
    display: str
    detail: str


def outermost(artifacts: list[Artifact]) -> list[Artifact]:
    """Listed locations not inside another listed location, so their sizes can be added."""
    paths = sorted({a.path.rstrip("/") for a in artifacts})
    outer = {p for p in paths if not any(p.startswith(q + "/") for q in paths if q != p)}
    seen: set[str] = set()
    kept = []
    for artifact in artifacts:
        path = artifact.path.rstrip("/")
        if path in outer and path not in seen:
            seen.add(path)
            kept.append(artifact)
    return kept


def disk_bytes(artifacts: list[Artifact], category: Category | None = None) -> int:
    """Bytes on disk for the outermost locations, optionally of one category."""
    return sum(
        a.size_bytes for a in outermost(artifacts) if category is None or a.category is category
    )


def _installed(audit: AuditReport) -> list[ToolReport]:
    return [t for t in audit.tools if t.installed]


def _secret_figure(tools: list[ToolReport]) -> Figure:
    scans = [t.secret_scan for t in tools if t.secret_scan]
    if not scans:
        return Figure("secrets", "Secret values found", None, "not scanned", "run without --doctor")
    total = sum(k.unique for scan in scans for k in scan.kinds)
    files = sum(scan.files_scanned for scan in scans)
    scope = (
        "distinct values"
        if len(scans) == 1
        else f"distinct within each tool's data, added across {len(scans)} tools"
    )
    return Figure(
        "secrets", "Secret values found", total, f"{total:,}", f"{scope}; {files:,} files scanned"
    )


def _keys_figure(audit: AuditReport) -> Figure:
    rows = keys.rows(audit)
    api = [r for r in rows if r.kind == keys.API_KEY]
    logins = sum(1 for r in rows if r.kind == keys.LOGIN)
    providers = sorted({r.provider for r in api}, key=str.lower)
    detail = f"distinct keys for {', '.join(providers)}" if api else "no API keys stored"
    return Figure(
        "api_keys",
        "API keys",
        len(api),
        str(len(api)),
        f"{detail}; {surface.plural(logins, 'OAuth login')} also stored",
    )


def _autostart_figure(rows: list[tuple[str, bool]]) -> Figure:
    auto = Counter(kind for kind, autostart in rows if autostart)
    parts = [surface.plural(n, KIND_NAMES.get(kind, kind)) for kind, n in auto.most_common()]
    total = sum(auto.values())
    return Figure(
        "autostart",
        "Run automatically",
        total,
        str(total),
        f"of {len(rows)} {'entry' if len(rows) == 1 else 'entries'}"
        + (f": {', '.join(parts)}" if parts else "")
        + " (listed as starting without being invoked)",
    )


def _disk_figure(artifacts: list[Artifact]) -> Figure:
    total = disk_bytes(artifacts)
    parts = [
        f"{human_size(size)} {what}"
        for size, what in (
            (disk_bytes(artifacts, Category.BINARY), "in listed install folders"),
            (disk_bytes(artifacts, Category.SESSION), "of conversations and history"),
        )
        if size
    ]
    count = surface.plural(len(outermost(artifacts)), "listed location")
    return Figure(
        "disk",
        "On disk",
        total,
        human_size(total),
        count + (f", including {' and '.join(parts)}" if parts else ""),
    )


def machine(
    audit: AuditReport, checklist: Checklist, extensions: list[tuple[str, bool]]
) -> list[Figure]:
    """Figures for the overview.

    Args:
        audit: The audit.
        checklist: The doctor checklist.
        extensions: ``(kind, autostart)`` for each extension entry, one per identity across tools.
    """
    tools = _installed(audit)
    findings = audit.all_exposures()
    host = sum(1 for x in findings if x.tool == "host")
    exposed = sum(1 for c in checklist if c.found)
    unchecked = sum(1 for c in checklist if c.unchecked)
    creds = [c for t in tools for c in t.credentials]
    readable = sum(1 for c in creds if c.readable_by_others)
    return [
        Figure(
            "tools",
            "Tools audited",
            len(tools),
            str(len(tools)),
            ", ".join(t.display_name for t in tools),
        ),
        Figure(
            "signals",
            "Signals to review",
            len(findings),
            str(len(findings)),
            f"{len(findings) - host} from tool checks, {host} from checks of this machine",
        ),
        Figure(
            "checks",
            "Checks with a signal",
            exposed,
            f"{exposed} of {len(checklist)}",
            f"{len(checklist) - exposed - unchecked} clear, {unchecked} not checked because "
            "their input is not recorded for that tool (same checks as --doctor)",
        ),
        Figure(
            "credentials",
            "Credential locations",
            len(creds),
            str(len(creds)),
            f"{readable} marked readable by other local accounts",
        ),
        _keys_figure(audit),
        _secret_figure(tools),
        _disk_figure([a for t in tools for a in t.artifacts]),
        _autostart_figure(extensions),
    ]


def approval(tool: ToolReport) -> Figure:
    """Whether approval is turned off, from the settings the no-approval check reads.

    The state is "not checked" when this tool's audit records none of those settings, so the
    absence of a finding is never shown as "asks before running".
    """
    found = next((x for x in tool.exposures if x.id == f"{tool.name}:no-approval"), None)
    label = "Approval turned off"
    if found:
        return Figure("approval", label, "found", "found", "; ".join(found.evidence))
    read = [s for s in tool.settings if s.key in rules.APPROVAL_KEYS]
    if read:
        checked = "; ".join(f"{s.key} = {s.value}" for s in read)
        return Figure(
            "approval",
            label,
            "not found",
            "not found",
            f"no recorded setting turns it off; read {checked}",
        )
    return Figure(
        "approval",
        label,
        "not checked",
        "not checked",
        "this audit records no approval setting for this tool",
    )


def for_tool(tool: ToolReport, checklist: Checklist) -> list[Figure]:
    """Figures for one tool's page."""
    checks = [c for c in checklist if c.scope == tool.display_name]
    readable = sum(1 for c in tool.credentials if c.readable_by_others)
    auto = sum(1 for x in tool.extensions if x.autostart)
    sessions = disk_bytes(tool.artifacts, Category.SESSION)
    session_count = sum(1 for a in outermost(tool.artifacts) if a.category is Category.SESSION)
    disk = _disk_figure(tool.artifacts)
    return [
        disk,
        Figure(
            "sessions",
            "Conversations and history",
            sessions,
            human_size(sessions),
            f"{surface.plural(session_count, 'session location')}",
        ),
        Figure(
            "credentials",
            "Credential locations",
            len(tool.credentials),
            str(len(tool.credentials)),
            f"{readable} marked readable by other local accounts",
        ),
        Figure(
            "extensions",
            "Extensions",
            len(tool.extensions),
            str(len(tool.extensions)),
            f"{auto} listed as starting without being invoked",
        ),
        Figure(
            "signals",
            "Signals to review",
            len(tool.exposures),
            str(len(tool.exposures)),
            f"{sum(1 for c in checks if c.found)} of {len(checks)} checks returned a signal, "
            f"{sum(1 for c in checks if c.unchecked)} not checked",
        ),
        _secret_figure([tool]),
        approval(tool),
    ]


def signals_matrix(audit: AuditReport) -> dict[str, dict[str, int]]:
    """Signals per attacker position and tool (``host`` for checks of this machine)."""
    columns = [t.name for t in _installed(audit)] + ["host"]
    matrix = {lens.value: dict.fromkeys(columns, 0) for lens in Lens}
    for exposure in audit.all_exposures():
        matrix[exposure.lens.value][exposure.tool] += 1
    return matrix


def disk_by_category(audit: AuditReport) -> list[dict[str, Any]]:
    """Bytes per category for each installed tool, outermost locations only."""
    return [
        {
            "tool": tool.name,
            "parts": {c.value: disk_bytes(tool.artifacts, c) for c in Category},
        }
        for tool in _installed(audit)
    ]


def method_summary(audit: AuditReport) -> str:
    """What the audit ran, counted from its own command log."""
    tool_runs = sum(1 for r in audit.executed if r.purpose in TOOL_RUN_PURPOSES)
    probe_runs = len(audit.executed) - tool_runs
    signed = sum(
        1 for v in audit.probe_validation if any(c.name == "Apple code signature" for c in v.checks)
    )
    network = "Live checks were enabled." if audit.live else "No network requests were made."
    probes = len(audit.probe_validation)
    which = f"All {probes}" if signed == probes else f"{signed} of the {probes}"
    signature = (
        f" {which} registered probes must pass an Apple code-signature check before they run."
        if signed
        else ""
    )
    return (
        f"The audit is read-only. It ran {surface.plural(len(audit.executed), 'command')}, each "
        f"by absolute path with a fixed PATH: {probe_runs} from its probe registry and "
        f"{tool_runs} of installed AI-tool binaries, limited to --version and --help."
        f"{signature} Secrets were read into memory only to derive metadata. {network}"
    )
