"""OpenCode account notes: sharing and revocation for the providers it stores logins for."""

from typing import Any

from ai_footprint.harnesses.account_notes import note, revoke_advice, unused_logins
from ai_footprint.model import AccountNote, ToolReport


def notes(report: ToolReport, config: dict[str, Any]) -> list[AccountNote]:
    """Account evidence for OpenCode, whose credentials belong to other providers."""
    share = config.get("share", "not set")
    providers = sorted({c.provider for c in report.credentials if not c.local_service})
    notes = [
        note(
            "data",
            f"Session sharing: share = {share}. Each provider's own data policy applies to "
            f"what OpenCode sends: {', '.join(providers) or 'none'}.",
            "opencode config",
            concern=share == "auto",
        ),
        note(
            "revoke",
            "Whether `opencode auth logout` revokes anything at the provider is not something "
            f"this audit can observe. {revoke_advice(providers)}",
            "OpenCode credential model",
        ),
    ]
    return notes + unused_logins(report)
