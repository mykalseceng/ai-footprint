"""Run every harness, the checks and the validators to produce one ``AuditReport``."""

import datetime
import time
from collections.abc import Sequence
from pathlib import Path

from ai_footprint import __version__, checks, daemons, hostscan, validate
from ai_footprint.checks import Checklist
from ai_footprint.harnesses import registry
from ai_footprint.harnesses.common import Context
from ai_footprint.host import collect_host
from ai_footprint.model import AuditReport, ToolPresence, ToolReport
from ai_footprint.system import System


def detect_tools(*, system: System, home: Path) -> list[ToolPresence]:
    """Which supported tools are installed, without running a full audit."""
    ctx = Context(home=home, system=system, now=time.time(), scan=False)
    return [harness.detect(ctx) for harness in registry().values()]


def run_audit(
    *,
    system: System,
    home: Path,
    tools: Sequence[str] | None = None,
    live: bool = False,
    scan: bool = True,
    workers: int | None = None,
    presences: Sequence[ToolPresence] = (),
) -> tuple[AuditReport, Checklist]:
    """Audit the selected tools.

    Args:
        system: Probe runner (swap for a fake in tests).
        home: Home directory to audit.
        tools: Harness names to audit; None audits every harness.
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
    harnesses = registry()
    reports: list[ToolReport] = []
    for name in harnesses if tools is None else tools:
        report = harnesses[name].collect(ctx, found.get(name))
        report.daemons = daemons.collect(ctx, report)
        reports.append(report)
    host.facts = hostscan.scan(home, system, reports)
    audit = AuditReport(
        generated_at=datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
        auditor_version=__version__,
        host=host,
        tools=reports,
        live=live,
        scanned=scan,
    )
    checklist = checks.evaluate(
        audit, checks.RuleContext(host=host, platform=system.platform, home=home)
    )
    audit.probe_validation = system.validate_probes()
    validate.validate_all(audit, system)
    audit.claim_validation = validate.validate_claims(
        audit, {name: harness.claims for name, harness in harnesses.items()}
    )
    audit.executed = list(system.executed)
    return audit, checklist
