"""Checks for what a stolen token reaches from anywhere."""

from ai_footprint.checks.base import RuleContext, exposure
from ai_footprint.harnesses.profile import Remedy
from ai_footprint.model import (
    REMOTE_CONTROL,
    UNUSED_LOGIN,
    Exposure,
    Fix,
    FixCommand,
    Lens,
    ToolReport,
)
from ai_footprint.text import join

CONNECTOR_SCOPES = ("user:mcp_servers", "api.connectors.read", "api.connectors.invoke")


def rule_connected_apps(report: ToolReport, ctx: RuleContext) -> list[Exposure]:
    """Tokens whose scopes let them use the apps connected to the account, named when recorded."""
    del ctx
    scopes = sorted(
        {
            scope
            for c in report.credentials
            for t in c.tokens
            for scope in t.scopes
            if scope in CONNECTOR_SCOPES
        }
    )
    if not scopes:
        return []
    apps = [x for x in report.extensions if x.kind == "connector"]
    named = sorted({x.name for x in apps})
    which = (
        f"The apps recorded on this machine are {join(named)}."
        if named
        else "Which apps are connected is not recorded on this machine; the provider's "
        "connected-apps settings list them."
    )
    return [
        exposure(
            report,
            "connected-apps",
            Lens.REMOTE,
            f"Anyone holding the {report.display_name} token can use the apps connected to your "
            f"account, because it carries {join(scopes)}. {which}",
            evidence=scopes + [f"{x.name}: {x.source}" for x in apps],
            fix=Fix(
                "Disconnect apps you do not use (the token keeps its scopes)",
                [
                    FixCommand(
                        "Remove unused connected apps in the provider's settings", manual=True
                    )
                ],
            ),
        )
    ]


def rule_shared_sessions(report: ToolReport, ctx: RuleContext) -> list[Exposure]:
    """Sessions published to share links."""
    shared = [s for s in report.settings if s.key == "shared sessions" and s.value not in {"0", ""}]
    auto = [s for s in report.settings if s.key == "share" and s.value == "auto"]
    if not shared and not auto:
        return []
    return [
        exposure(
            report,
            "shared",
            Lens.REMOTE,
            "Sessions are published to share links; anyone with a link can read them.",
            evidence=[f"{s.key} = {s.value}" for s in shared + auto],
            fix=ctx.remedy(report, Remedy.DISABLE_SHARE)
            or Fix(
                "Unshare and turn off auto-share",
                [FixCommand("Turn session sharing off in the tool's settings", manual=True)],
            ),
        )
    ]


def _note_signal(report: ToolReport, signal: str, rule_id: str, fix: Fix) -> list[Exposure]:
    notes = [n for n in report.account if n.signal == signal and n.concern]
    if not notes:
        return []
    return [
        exposure(
            report,
            rule_id,
            Lens.REMOTE,
            " ".join(n.text for n in notes),
            evidence=[n.source for n in notes],
            fix=fix,
        )
    ]


def rule_remote_control(report: ToolReport, ctx: RuleContext) -> list[Exposure]:
    """Remote control of the tool on this machine is enabled, or a device is paired."""
    del ctx
    fix = Fix(
        "Turn remote control off where you do not use it, and remove devices you do not know",
        [FixCommand("Review paired devices and remote access in the tool's settings", manual=True)],
    )
    return _note_signal(report, REMOTE_CONTROL, "remote-control", fix)


def rule_unused_logins(report: ToolReport, ctx: RuleContext) -> list[Exposure]:
    """Stored logins that are no longer refreshed but can still be renewed."""
    del ctx
    fix = Fix(
        "Log out of providers you no longer use with this tool",
        [FixCommand("Remove the stored login, then revoke it at the provider", manual=True)],
    )
    return _note_signal(report, UNUSED_LOGIN, "unused-logins", fix)
