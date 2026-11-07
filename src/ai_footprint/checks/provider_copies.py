"""Checks for copies of your work the provider keeps."""

from ai_footprint.checks.base import RuleContext, exposure
from ai_footprint.harnesses.profile import Remedy
from ai_footprint.model import (
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
