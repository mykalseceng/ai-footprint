"""OpenCode (``opencode``)."""

from ai_footprint.harnesses.base import Harness
from ai_footprint.harnesses.common import Context
from ai_footprint.harnesses.opencode import account, collector
from ai_footprint.model import ToolPresence, ToolReport


def _collect(ctx: Context, found: ToolPresence) -> ToolReport:
    report, config = collector.collect(ctx, found)
    if report.installed:
        report.account = account.notes(report, config)
    return report


HARNESS = Harness(
    profile=collector.PROFILE,
    collect_fn=_collect,
    extra_claims=collector.EXTRA_CLAIMS,
)
