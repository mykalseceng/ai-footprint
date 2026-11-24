"""Checks for copies of your work and usage the provider keeps."""

from ai_footprint.checks.base import RuleContext, exposure
from ai_footprint.harnesses.profile import Remedy
from ai_footprint.model import (
    OTHER_TOOL_LOGIN,
    USAGE,
    AccountNote,
    Exposure,
    Fix,
    FixCommand,
    Lens,
    ToolReport,
)


def rule_account_data(report: ToolReport, ctx: RuleContext) -> list[Exposure]:
    """Copies of your work kept by the provider: training, cloud tasks, connectors."""
    notes = [n for n in report.account if n.topic == "data" and n.concern]
    if not notes:
        return []
    return [
        exposure(
            report,
            "account-data",
            Lens.COPIES,
            " ".join(n.text for n in notes),
            evidence=[n.source for n in notes],
            fix=ctx.remedy(report, Remedy.DATA_CONTROLS)
            or Fix(
                "Review the provider's data settings",
                [FixCommand("Review the provider's data settings", manual=True)],
            ),
        )
    ]


def _telemetry_fix(report: ToolReport, ctx: RuleContext) -> Fix:
    return ctx.remedy(report, Remedy.TELEMETRY_OFF) or Fix(
        "Turn off the tool's usage data",
        [FixCommand("Turn off usage data in the tool's settings", manual=True)],
    )


def _usage_exposure(
    report: ToolReport, ctx: RuleContext, rule_id: str, notes: list[AccountNote]
) -> list[Exposure]:
    if not notes:
        return []
    return [
        exposure(
            report,
            rule_id,
            Lens.COPIES,
            " ".join(n.text for n in notes),
            evidence=[n.source for n in notes],
            fix=_telemetry_fix(report, ctx),
        )
    ]


def rule_usage_data(report: ToolReport, ctx: RuleContext) -> list[Exposure]:
    """Usage data the tool sends its vendor, on by default or by a setting."""
    notes = [n for n in report.account if n.topic == USAGE and n.concern and not n.signal]
    return _usage_exposure(report, ctx, "usage-data", notes)


def rule_other_logins(report: ToolReport, ctx: RuleContext) -> list[Exposure]:
    """Identifiers read from another tool's login file and sent with the tool's usage data."""
    notes = [n for n in report.account if n.signal == OTHER_TOOL_LOGIN and n.concern]
    return _usage_exposure(report, ctx, "other-logins", notes)
