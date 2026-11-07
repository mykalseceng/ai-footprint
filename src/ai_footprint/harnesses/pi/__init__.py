"""pi (``pi``)."""

from ai_footprint.harnesses.base import Harness
from ai_footprint.harnesses.common import Context
from ai_footprint.harnesses.pi import account, collector
from ai_footprint.model import ToolPresence, ToolReport


def _collect(ctx: Context, found: ToolPresence) -> ToolReport:
    report, settings = collector.collect(ctx, found)
    if report.installed:
        report.account = account.notes(ctx, report, settings)
    return report


HARNESS = Harness(
    profile=collector.PROFILE,
    collect_fn=_collect,
    binaries_fn=collector.binaries,
    extra_claims=collector.EXTRA_CLAIMS,
)
