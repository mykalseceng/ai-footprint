"""Checks for text that steers the model into running commands as you."""

from pathlib import Path

from ai_footprint import harnesses
from ai_footprint.checks.base import RuleContext, exposure
from ai_footprint.harnesses.profile import Remedy
from ai_footprint.model import (
    RUNNING_BYPASS,
    THREADS_WITHOUT_APPROVAL,
    Exposure,
    Fix,
    FixCommand,
    Lens,
    ToolReport,
)
from ai_footprint.text import join, plural


def approval_keys() -> frozenset[str]:
    """Every setting the no-approval check reads, across all harnesses."""
    keys = {key for h in harnesses.registry().values() for key in h.profile.approval_off}
    return frozenset({*keys, RUNNING_BYPASS, THREADS_WITHOUT_APPROVAL})


def rule_no_approval(report: ToolReport, ctx: RuleContext) -> list[Exposure]:
    """Commands run without approval or sandbox: a config value, or sessions started that way."""
    off = ctx.approval_off(report)
    configured = [s for s in report.settings if off.get(s.key) == s.value]
    running = [s for s in report.settings if s.key == RUNNING_BYPASS]
    threads = [s for s in report.settings if s.key == THREADS_WITHOUT_APPROVAL and s.concern]
    if not configured and not running and not threads:
        return []
    observed = [f"{s.key} = {s.value}" for s in configured]
    observed += [
        f"{plural(len(s.value.split(', ')), 'running session')} started with "
        "--dangerously-skip-permissions"
        for s in running
    ]
    observed += [f"{s.key}: {s.value}" for s in threads]
    return [
        exposure(
            report,
            "no-approval",
            Lens.MODEL,
            f"{report.display_name} skips approval prompts in some sessions "
            f"({join(observed)}). In those sessions, text that reaches the model (a web page, a "
            "repo file, an MCP result, an instruction file) can become commands running as you, "
            "limited only by the sandbox, deny rules and hooks that still apply.",
            evidence=[f"{s.key} = {s.value}" for s in configured + running + threads],
            fix=_no_approval_fix(report, ctx),
        )
    ]


def _no_approval_fix(report: ToolReport, ctx: RuleContext) -> Fix:
    return ctx.remedy(report, Remedy.REQUIRE_APPROVAL) or Fix(
        "Require approval for shell and edit tools",
        [FixCommand("Turn approval prompts back on in the tool's settings", manual=True)],
    )


_LOADED_AS = {
    "global": "is read as your instructions every session",
    "project": "is read as your instructions in that project",
    "memory": "is the auto-memory index loaded every session in that project",
    "agent": "defines a subagent",
    "command": "defines a slash command",
}


def rule_instructions(report: ToolReport, ctx: RuleContext) -> list[Exposure]:
    """Instruction files whose content steers the model."""
    flagged = [f for f in report.instructions if f.markers and f.loaded_by[0] == report.name]
    return [
        exposure(
            report,
            f"instructions-{index}",
            Lens.MODEL,
            f"{ctx.display(f.path)} {_LOADED_AS.get(f.scope, 'is loaded')} and contains "
            f"{'; '.join(f.markers)}.",
            evidence=[f"loaded by {', '.join(f.loaded_by)}; mode {f.mode}"],
            fix=Fix(
                "Review and remove the flagged lines",
                [
                    FixCommand(
                        f"Edit {ctx.display(f.path)} and delete what you did not write or "
                        "no longer need",
                        manual=True,
                    )
                ],
            ),
        )
        for index, f in enumerate(flagged)
    ]


BROAD_TRUST = (
    "Documents",
    "Downloads",
    "Desktop",
    "tmp",
    "Library/Application Support",
    "node_modules",
)
"""Folder names whose contents come from many sources, not one project."""


def _broad(folder: Path, home: Path) -> bool:
    path = f"{folder}/"
    return folder == home or any(f"/{name}/" in path for name in BROAD_TRUST)


def _inside(parent: Path, folder: Path) -> bool:
    """The folder itself, or a tool's dot-folder directly inside it (``.claude``, ``.pi``)."""
    return parent == folder or (parent.parent == folder and parent.name.startswith("."))


def _carried_instructions(report: ToolReport, folder: Path) -> list[str]:
    """Project instruction files this tool loads from inside a trusted folder."""
    return [
        i.path
        for i in report.instructions
        if i.scope == "project" and _inside(Path(i.path).parent, folder)
    ]


def rule_trust(report: ToolReport, ctx: RuleContext) -> list[Exposure]:
    """Trusted folders: broad ones, writable ones, and those holding instruction files."""
    folders = [Path(f) for f in report.trusted_folders]
    if not folders:
        return []
    broad = [f for f in folders if _broad(f, ctx.home)]
    carried = {f: _carried_instructions(report, f) for f in folders}
    carriers = [f for f in folders if carried[f]]
    if not broad and not carriers:
        return []
    statement = f"{report.display_name} trusts {plural(len(folders), 'folder')}."
    if carriers:
        statement += (
            f" {len(carriers)} of them {'holds' if len(carriers) == 1 else 'hold'} "
            f"instruction files {report.display_name} loads."
        )
    if broad:
        named = join([ctx.display(str(f)) for f in broad[:5]])
        statement += f" Broad folders on the list: {named}."
    return [
        exposure(
            report,
            "trust",
            Lens.MODEL,
            statement,
            evidence=[ctx.display(p) for f in carriers for p in carried[f]][:10],
            fix=ctx.remedy(report, Remedy.WITHDRAW_TRUST)
            or Fix(
                "Withdraw trust from folders you do not own or no longer use",
                [
                    FixCommand(
                        "Withdraw trust from those folders in the tool's settings", manual=True
                    )
                ],
            ),
        )
    ]
