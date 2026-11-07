"""Checks for what a stolen token reaches from anywhere."""

from ai_footprint.checks.base import RuleContext, exposure
from ai_footprint.harnesses.profile import Remedy
from ai_footprint.model import (
    Exposure,
    Fix,
    FixCommand,
    Lens,
    ToolReport,
)
from ai_footprint.text import join, plural

CONNECTOR_SCOPES = ("user:mcp_servers", "api.connectors.read", "api.connectors.invoke")


def rule_token_reach(report: ToolReport, ctx: RuleContext) -> list[Exposure]:
    """Tokens whose scopes name the provider's connectors."""
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
    connectors = [e.name for e in report.extensions if e.kind == "connector"]
    used = (
        f" This CLI has connected to {join(connectors)} (recorded in its config)."
        if connectors
        else ""
    )
    return [
        exposure(
            report,
            "token-reach",
            Lens.REMOTE,
            f"The {report.display_name} token carries {plural(len(scopes), 'connector scope')}: "
            f"{', '.join(scopes)}.{used}",
            evidence=scopes + connectors,
            fix=Fix(
                "Disconnect connectors you do not use (the token keeps its scopes)",
                [
                    FixCommand(
                        "Remove unused connectors in the provider's web settings", manual=True
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


def rule_account_signals(report: ToolReport, ctx: RuleContext) -> list[Exposure]:
    """Local signs that a credential was used elsewhere or can be driven remotely."""
    del ctx
    notes = [n for n in report.account if n.topic == "detect" and n.concern]
    if not notes:
        return []
    return [
        exposure(
            report,
            "account-signals",
            Lens.REMOTE,
            " ".join(n.text for n in notes),
            evidence=[n.source for n in notes],
            fix=Fix(
                "Check active sessions and devices, then revoke what you do not recognise",
                [
                    FixCommand(
                        "Review signed-in sessions and paired devices in the provider's "
                        "security settings",
                        manual=True,
                    )
                ],
            ),
        )
    ]
