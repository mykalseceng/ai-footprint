"""Checks for what another account on this machine can read or reach."""

from pathlib import Path

from ai_footprint.checks.base import RuleContext, exposure, quote
from ai_footprint.model import (
    Artifact,
    Category,
    Exposure,
    Fix,
    FixCommand,
    Lens,
    ToolReport,
)


def rule_credentials_exposed(report: ToolReport, ctx: RuleContext) -> list[Exposure]:
    """Credential stores readable by other local accounts."""
    exposed = [c for c in report.credentials if c.readable_by_others]
    if not exposed:
        return []
    others = ", ".join(ctx.host.other_users) or "any future local account"
    paths = sorted({c.location for c in exposed})
    commands = [FixCommand(f"chmod 600 {quote(p)}") for p in paths if Path(p).is_file()]
    commands += [
        FixCommand(f"chmod 700 {quote(str(Path(p).parent))}") for p in paths if Path(p).is_file()
    ]
    commands.append(FixCommand("Rotate every credential listed: assume it was copied", manual=True))
    providers = sorted({c.provider for c in exposed})
    return [
        exposure(
            report,
            "creds-readable",
            Lens.ACCOUNT,
            f"{others} can read {len(exposed)} {report.display_name} credential(s) "
            f"({', '.join(providers)}) straight from {', '.join(ctx.display(p) for p in paths)}.",
            evidence=[f"{c.provider}: {c.protection}" for c in exposed],
            fix=Fix("Restrict the files, then rotate the credentials", commands),
        )
    ]


def _contents_readable(artifact: Artifact, shared_groups: set[str]) -> bool:
    """Another account can read the file, or at least one file inside the folder."""
    if artifact.other_readable:
        return not artifact.is_dir or artifact.other_readable_files > 0
    if artifact.group_readable in shared_groups:
        return not artifact.is_dir or artifact.group_readable_files > 0
    return False


def rule_exposed_data(report: ToolReport, ctx: RuleContext) -> list[Exposure]:
    """Session, config and log data readable by other accounts, directly or through a group."""
    shared_groups = {g for groups in ctx.host.other_user_groups.values() for g in groups}
    exposed = [
        a
        for a in report.artifacts
        if _contents_readable(a, shared_groups)
        and a.category in {Category.SESSION, Category.CONFIG, Category.LOG, Category.INSTRUCTIONS}
    ]
    if not exposed or not ctx.host.other_users:
        return []
    return [
        exposure(
            report,
            "data-readable",
            Lens.ACCOUNT,
            f"{', '.join(ctx.host.other_users)} can read {len(exposed)} {report.display_name} "
            f"data stores, including {', '.join(a.label.lower() for a in exposed[:4])}.",
            evidence=[f"{ctx.display(a.path)} ({a.mode}): {a.description}" for a in exposed[:12]],
            fix=Fix(
                "Restrict permissions (re-check after updates)",
                [
                    FixCommand(f"chmod {'700' if a.is_dir else '600'} {quote(a.path)}")
                    for a in exposed
                ],
            ),
        )
    ]


def rule_open_server(report: ToolReport, ctx: RuleContext) -> list[Exposure]:
    """Local agent servers without authentication."""
    del ctx
    open_servers = [s for s in report.settings if s.key.startswith("local server") and s.concern]
    if not open_servers:
        return []
    pids = [str(p.pid) for p in report.processes if "serve" in p.command]
    return [
        exposure(
            report,
            "open-server",
            Lens.ACCOUNT,
            f"The local {report.display_name} server's own registration records no password, "
            "so any local process or account that reaches its port can run prompts and tools "
            "as you.",
            evidence=[f"{s.key}: {s.value}" for s in open_servers],
            fix=Fix("Stop the server", [FixCommand(f"kill {' '.join(pids) or '<pid>'}")]),
        )
    ]
