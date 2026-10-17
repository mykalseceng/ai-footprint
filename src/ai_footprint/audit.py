"""Run collectors, rules and validators to produce one ``AuditReport``."""

import datetime
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ai_footprint import __version__, accounts, daemons, hostscan, rules, validate
from ai_footprint.collectors import claude, codex, opencode, pi
from ai_footprint.collectors.common import Claim, Context
from ai_footprint.host import collect_host
from ai_footprint.model import AuditReport, ToolPresence, ToolReport
from ai_footprint.rules import Checklist
from ai_footprint.system import System

Collector = Callable[[Context, ToolPresence | None], tuple[ToolReport, dict[str, Any]]]
Detector = Callable[[Context], ToolPresence]


@dataclass(frozen=True)
class ToolSpec:
    """A supported AI tool: how to find it and how to audit it."""

    name: str
    display_name: str
    collect: Collector
    detect: Detector
    claims: tuple[Claim, ...]


TOOLS: dict[str, ToolSpec] = {
    spec.name: spec
    for spec in (
        ToolSpec(claude.NAME, claude.DISPLAY, claude.collect, claude.detect, claude.CLAIMS),
        ToolSpec(codex.NAME, codex.DISPLAY, codex.collect, codex.detect, codex.CLAIMS),
        ToolSpec(
            opencode.NAME, opencode.DISPLAY, opencode.collect, opencode.detect, opencode.CLAIMS
        ),
        ToolSpec(pi.NAME, pi.DISPLAY, pi.collect, pi.detect, pi.CLAIMS),
    )
}


def detect_tools(*, system: System, home: Path) -> list[ToolPresence]:
    """Which supported tools are installed, without running a full audit."""
    ctx = Context(home=home, system=system, now=time.time(), scan=False)
    return [spec.detect(ctx) for spec in TOOLS.values()]


def run_audit(
    *,
    system: System,
    home: Path,
    tools: Sequence[str] = tuple(TOOLS),
    live: bool = False,
    scan: bool = True,
    workers: int | None = None,
    presences: Sequence[ToolPresence] = (),
) -> tuple[AuditReport, Checklist]:
    """Audit the selected tools.

    Args:
        system: Probe runner (swap for a fake in tests).
        home: Home directory to audit.
        tools: Names from ``TOOLS`` to audit.
        live: Allow opt-in network checks.
        scan: Run the full secret scan.
        workers: Scanner process count.
        presences: Results of ``detect_tools`` already run; a tool without one is detected
            here. Reusing them probes each binary once per audit.

    Returns:
        The report and the doctor checklist.
    """
    ctx = Context(home=home, system=system, now=time.time(), live=live, scan=scan, workers=workers)
    host = collect_host(system, home)
    found = {p.name: p for p in presences}
    reports: list[ToolReport] = []
    facts: dict[str, dict[str, Any]] = {}
    for name in tools:
        report, tool_facts = TOOLS[name].collect(ctx, found.get(name))
        report.daemons = daemons.collect(ctx, report)
        report.account = accounts.collect(ctx, report, tool_facts)
        reports.append(report)
        facts[name] = tool_facts
    host.facts = hostscan.scan(home, system, reports)
    audit = AuditReport(
        generated_at=datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
        auditor_version=__version__,
        host=host,
        tools=reports,
        live=live,
        scanned=scan,
    )
    checklist = rules.evaluate(
        audit, rules.RuleContext(host=host, platform=system.platform, home=home, facts=facts)
    )
    audit.probe_validation = system.validate_probes()
    validate.validate_all(audit, system)
    audit.claim_validation = validate.validate_claims(
        audit, {name: spec.claims for name, spec in TOOLS.items()}
    )
    audit.executed = list(system.executed)
    return audit, checklist
