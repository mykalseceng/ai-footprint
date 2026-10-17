"""Terminal output: the attack-surface narrative, the doctor checklist, and validation."""

import os
import shutil
import textwrap
from collections import Counter
from collections.abc import Iterable

from ai_footprint import figures, reportcheck, surface
from ai_footprint.fsinfo import human_size
from ai_footprint.model import AuditReport, CommandValidation, Fix, ToolPresence
from ai_footprint.rules import Check

_COLORS = {
    "REVIEW": "31",
    "clear": "32",
    "unchecked": "33",
    "PASS": "32",
    "FAIL": "31",
    "dim": "2",
    "bold": "1",
}


class Style:
    """ANSI styling that switches off for pipes and when NO_COLOR is set."""

    def __init__(self, *, enabled: bool) -> None:
        self.enabled = enabled

    @classmethod
    def for_stream(cls, *, isatty: bool) -> "Style":
        """Enable colour only for terminals without NO_COLOR."""
        return cls(enabled=isatty and "NO_COLOR" not in os.environ)

    def __call__(self, text: str, tone: str) -> str:
        """Wrap ``text`` in the ANSI code for ``tone`` when styling is enabled."""
        if not self.enabled or tone not in _COLORS:
            return text
        return f"\033[{_COLORS[tone]}m{text}\033[0m"


def _wrap(text: str, first: str, rest: str | None = None) -> list[str]:
    width = min(shutil.get_terminal_size((100, 20)).columns, 110)
    return textwrap.wrap(
        text, width=width, initial_indent=first, subsequent_indent=rest or first
    ) or [first]


def validation_label(validation: CommandValidation) -> tuple[str, str]:
    """(label, tone) describing what validation established for one command."""
    names = [c.name for c in validation.checks]
    if not validation.ok:
        failed = next(c for c in validation.checks if not c.passed)
        return f"✗ {failed.name}: {failed.detail}", "FAIL"
    if names == ["manual step"]:
        return "manual step (not machine-checkable)", "dim"
    if names[0] == "manual step":
        return "✓ config keys confirmed in installed binary", "PASS"
    return "✓ validated", "PASS"


def fix_lines(fix: Fix, style: Style, indent: str) -> list[str]:
    """Render a fix with each command's validation result."""
    lines = [f"{indent}→ {fix.summary}"]
    for cmd, validation in zip(fix.commands, fix.validations, strict=False):
        lines.append(f"{indent}  {cmd.text if cmd.manual else '$ ' + cmd.text}")
        label, tone = validation_label(validation)
        lines.append(f"{indent}    {style(label, tone)}")
    return lines


def render_narrative(audit: AuditReport, style: Style) -> list[str]:
    """The attack-surface story: headline paragraph, then each attacker position."""
    story = surface.for_machine(audit)
    out = [style("Attack surface", "bold"), *_wrap(" ".join(story.headline), "  "), ""]
    for view in story.lenses:
        out.append(style(view.lens.title, "bold") + style(f"  {view.lens.question}", "dim"))
        if not view.points:
            out.append(style("  nothing found from this position", "dim"))
        for point in view.points:
            out.extend(_wrap(f"{point.tool}: {point.text}", "  · ", "    "))
        out.append("")
    return out


def render_doctor(audit: AuditReport, checklist: Iterable[Check], style: Style) -> tuple[str, int]:
    """Doctor view: each check marked REVIEW, clear or not checked, with validated fixes.

    Returns:
        The text and the exit code (1 when anything needs review or any command is invalid).
    """
    host = audit.host
    out = [
        style("ai-footprint doctor", "bold")
        + style(f"  ·  {host.os}  ·  {host.user}@{host.hostname}  ·  {audit.generated_at}", "dim"),
        "",
    ]
    counts: Counter[str] = Counter()
    scope = None
    for name, check, found, unchecked in checklist:
        if name != scope:
            scope = name
            out.append(style(name, "bold"))
        status = "REVIEW" if found else "unchecked" if unchecked else "clear"
        counts[status] += 1
        if unchecked:
            out.append(f"  {style('not checked', 'unchecked')}  {check} ({unchecked})")
            continue
        out.append(f"  {style(status.ljust(7), status)}  {check}")
        for exposure in found:
            out.extend(_wrap(exposure.statement, "             "))
            if exposure.fix:
                out.extend(fix_lines(exposure.fix, style, indent="             "))
    out.extend(["", *_validation_summary(audit, style)])
    commands_ok = all(v.ok for v in _validations(audit)) and all(
        v.ok for v in audit.probe_validation
    )
    code = 1 if counts["REVIEW"] or not commands_ok else 0
    out.append(
        f"Result: {style(str(counts['REVIEW']) + ' to review', 'REVIEW')} · "
        f"{style(str(counts['clear']) + ' clear', 'clear')} · "
        f"{style(str(counts['unchecked']) + ' not checked', 'unchecked')}  (exit {code})"
    )
    out.append(
        style("Secret scan skipped in doctor mode; run without --doctor for the full audit.", "dim")
    )
    return "\n".join(out), code


def _validations(audit: AuditReport) -> list[CommandValidation]:
    return [v for x in audit.all_exposures() if x.fix for v in x.fix.validations]


def _validation_summary(audit: AuditReport, style: Style) -> list[str]:
    probes = audit.probe_validation
    unique = list({v.command: v for v in _validations(audit)}.values())
    bad_probes = [v for v in probes if not v.ok]
    bad_cmds = [v for v in unique if not v.ok]
    claims = [c for v in audit.claim_validation for c in v.checks]
    bad_claims = [v for v in audit.claim_validation if not v.ok]
    lines = [
        f"Probe binaries: {len(probes) - len(bad_probes)}/{len(probes)} verified "
        "(absolute path, not group/other-writable, Apple-signed on macOS)",
        f"Fix commands:   {len(unique) - len(bad_cmds)}/{len(unique)} validated "
        "(syntax, programs, targets, subcommands, config keys)",
        f"Tool claims:    {sum(c.passed for c in claims)}/{len(claims)} found in the installed "
        "binaries (endpoints, signature traits, config keys, log and behaviour markers)",
        f"Commands run by this audit: {len(audit.executed)} (all read-only)",
    ]
    for v in bad_probes + bad_cmds + bad_claims:
        failed = "; ".join(f"{c.name}: {c.detail}" for c in v.checks if not c.passed)
        lines.append(style(f"  ✗ {v.command[:100]} → {failed}", "FAIL"))
    return lines


def render_summary(audit: AuditReport, style: Style, outputs: list[tuple[str, str]]) -> str:
    """Audit output: tools found, the narrative, validation, and labelled output paths."""
    out = [
        style("ai-footprint", "bold")
        + style(f"  ·  {audit.host.os}  ·  {audit.host.user}@{audit.host.hostname}", "dim"),
        "",
    ]
    for tool in audit.tools:
        if not tool.installed:
            out.append(f"  {tool.display_name:<12} not installed")
            continue
        version = tool.binaries[0].version if tool.binaries else "?"
        scan = tool.secret_scan
        scanned = (
            f"scanned {scan.files_scanned:,} files / {human_size(scan.bytes_scanned)} in "
            f"{scan.seconds}s"
            if scan
            else "not scanned"
        )
        listed = sum(1 for a in figures.outermost(tool.artifacts) if a.exists)
        size = human_size(figures.disk_bytes(tool.artifacts))
        out.append(
            f"  {tool.display_name:<12} v{version:<10} {size:>9} in "
            f"{surface.plural(listed, 'listed location')} · {scanned}"
        )
    out.append("")
    out.extend(render_narrative(audit, style))
    out.extend([*_validation_summary(audit, style), ""])
    out.extend(f"{label + ':':<11}{path}" for label, path in outputs)
    return "\n".join(out)


def render_validation(audit: AuditReport, style: Style) -> tuple[str, int]:
    """Validation-only view: every probe and fix command with each check.

    Returns:
        The text and exit code (1 when any probe or command fails a check).
    """
    out = [style("ai-footprint validate", "bold"), "", style("Probe binaries", "bold")]
    for validation in audit.probe_validation:
        out.extend(_validation_block(validation, style))
    out.extend(["", style("Fix commands", "bold")])
    for validation in {v.command: v for v in _validations(audit)}.values():
        out.extend(_validation_block(validation, style))
    out.extend(["", style("Tool claims", "bold")])
    for validation in audit.claim_validation:
        out.extend(_validation_block(validation, style))
    out.extend(["", style("Report and dashboard pages", "bold")])
    for validation in audit.report_validation:
        out.extend(_validation_block(validation, style))
    out.extend(["", style("Figures", "bold")])
    for validation in audit.figure_validation:
        out.extend(_validation_block(validation, style))
    out.extend(["", style("CLI options", "bold")])
    for validation in audit.option_validation:
        out.extend(_validation_block(validation, style))
    options_ok = sum(v.ok for v in audit.option_validation)
    layout_ok = sum(v.ok for v in audit.report_validation)
    figures_ok = sum(v.ok for v in audit.figure_validation)
    out.extend(["", *_validation_summary(audit, style)])
    out.append(
        f"CLI options:    {options_ok}/{len(audit.option_validation)} checks passed "
        "(examples parse and select tools, help text, defaults, exclusive modes)"
    )
    out.append(
        f"Pages:          {layout_ok}/{len(audit.report_validation)} pass "
        f"(report: cells ≤ {reportcheck.MAX_CELL} chars, tables ≤ {reportcheck.MAX_ROWS} rows, "
        f"tokens ≤ {reportcheck.MAX_RUN} chars; both: one-sentence answers, one fact per cell, "
        "one date format, every extension row says what it does)"
    )
    out.append(
        f"Figures:        {figures_ok}/{len(audit.figure_validation)} groups match an independent "
        "recount of the run's data (tiles, signals grid, disk chart, checklist, method, headlines)"
    )
    failed = (
        any(not v.ok for v in audit.probe_validation)
        or any(not v.ok for v in _validations(audit))
        or any(not v.ok for v in audit.claim_validation)
        or any(not v.ok for v in audit.option_validation)
        or any(not v.ok for v in audit.report_validation)
        or any(not v.ok for v in audit.figure_validation)
    )
    return "\n".join(out), int(failed)


def _validation_block(validation: CommandValidation, style: Style) -> list[str]:
    head = style("PASS", "PASS") if validation.ok else style("FAIL", "FAIL")
    lines = [f"  {head}  {validation.command}"]
    for check in validation.checks:
        mark = style("✓", "PASS") if check.passed else style("✗", "FAIL")
        lines.append(style(f"          {mark} {check.name}: {check.detail}", "dim"))
    return lines


def render_list(presences: list[ToolPresence], style: Style, *, home: str) -> str:
    """Supported tools, which are installed, their versions, binaries and data folders."""
    out = [style("Supported AI tools", "bold"), ""]
    for tool in presences:
        if not tool.installed:
            out.append(
                f"  {style('-', 'dim')} {tool.name:<9} {tool.display_name:<12} "
                + style("not installed", "dim")
            )
            continue
        version = next((b.version for b in tool.binaries if b.version), "?")
        out.append(
            f"  {style('✓', 'clear')} {tool.name:<9} {tool.display_name:<12} v{version:<10}"
            f" {human_size(tool.size_bytes):>9} on disk"
        )
        for binary in tool.binaries:
            shadow = "" if binary is tool.binaries[0] else style("  (shadowed on PATH)", "dim")
            out.append(
                style(
                    f"      binary  {binary.path.replace(home, '~', 1)} v{binary.version or '?'}",
                    "dim",
                )
                + shadow
            )
        out.extend(
            style(f"      data    {path.replace(home, '~', 1)}", "dim") for path in tool.data_paths
        )
    installed = [t.name for t in presences if t.installed]
    out.append("")
    if installed:
        out.append("Audit all:      ai-footprint all")
        out.append(f"Audit some:     ai-footprint {' '.join(installed[:2])}")
    else:
        out.append("None of the supported tools are installed.")
    return "\n".join(out)
