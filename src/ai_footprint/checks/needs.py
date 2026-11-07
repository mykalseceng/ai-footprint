"""What each check needs from the collected data before it can run.

Each returns "" when the input the check reads was recorded for this tool, else the reason
the check could not run. A check that ran and found nothing is clear; one that could not run
says so.
"""

from ai_footprint.checks.base import RuleContext
from ai_footprint.checks.steering import approval_keys
from ai_footprint.model import (
    StoreKind,
    ToolReport,
)

# Each returns "" when the input the check reads was recorded for this tool, else the reason
# the check could not run. A check that ran and found nothing is clear; one that could not
# run says so.


def needs_approval_setting(report: ToolReport, ctx: RuleContext) -> str:
    """Why the check cannot run without a recorded approval setting, or ""."""
    del ctx
    if any(s.key in approval_keys() for s in report.settings):
        return ""
    return f"this audit records no approval setting for {report.display_name}"


def needs_scopes(report: ToolReport, ctx: RuleContext) -> str:
    """Why the check cannot run without a recorded scopes, or ""."""
    del ctx
    if any(t.scopes for c in report.credentials for t in c.tokens):
        return ""
    return "no stored token records its scopes"


def needs_share_setting(report: ToolReport, ctx: RuleContext) -> str:
    """Why the check cannot run without a recorded share setting, or ""."""
    del ctx
    if any(s.key in {"shared sessions", "share"} for s in report.settings):
        return ""
    return f"this audit records no share setting for {report.display_name}"


def needs_keychain(report: ToolReport, ctx: RuleContext) -> str:
    """Why the check cannot run without a recorded keychain, or ""."""
    del ctx
    if any(c.store is StoreKind.KEYCHAIN for c in report.credentials):
        return ""
    return "no credential is stored in the Keychain"


def needs_credentials(report: ToolReport, ctx: RuleContext) -> str:
    """Why the check cannot run without a recorded credentials, or ""."""
    del ctx
    return "" if report.credentials else "no stored credentials were found"


def needs_scan(report: ToolReport, ctx: RuleContext) -> str:
    """Why the check cannot run without a recorded scan, or ""."""
    del ctx
    return "" if report.secret_scan else "the secret scan runs only in the full audit"


def needs_local_mcp(report: ToolReport, ctx: RuleContext) -> str:
    """Why the check cannot run without a recorded local mcp, or ""."""
    del ctx
    if any(x.kind == "mcp" and x.access == "stdio" for x in report.extensions):
        return ""
    return "no local MCP server command to check"


def needs_other_accounts(report: ToolReport, ctx: RuleContext) -> str:
    """Why the check cannot run without a recorded other accounts, or ""."""
    del report
    return "" if ctx.host.other_users else "there are no other local accounts"


def needs_local_server(report: ToolReport, ctx: RuleContext) -> str:
    """Why the check cannot run without a recorded local server, or ""."""
    del ctx
    if any(s.key.startswith("local server") for s in report.settings):
        return ""
    if any(s.key.startswith("listening server") for s in report.settings):
        return "no registration on disk records the listening server's password"
    return f"this audit records no local server for {report.display_name}"


def needs_trusted_folders(report: ToolReport, ctx: RuleContext) -> str:
    """Why the check cannot run without a recorded trusted folders, or ""."""
    del ctx
    return "" if report.trusted_folders else "no trusted folders are recorded"


def needs_data_notes(report: ToolReport, ctx: RuleContext) -> str:
    """Why the check cannot run without a recorded data notes, or ""."""
    del ctx
    if any(n.topic == "data" for n in report.account):
        return ""
    return "no data-use setting is recorded"


def needs_signal_source(report: ToolReport, ctx: RuleContext) -> str:
    """Why the check cannot run without a recorded signal source, or ""."""
    if ctx.can_signal(report):
        return ""
    return f"nothing on disk records where else the {report.display_name} token is used"
